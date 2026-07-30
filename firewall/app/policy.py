"""Движок решений: правила, списки, лимиты.

ПОРЯДОК РАЗБОРА — он же то, что видит человек в вебморде:

  1. Режим тула        — тул выключен (`blocked`/`hidden`) → отказ, дальше не смотрим.
  2. Правила           — по приоритету, ПЕРВОЕ совпавшее решает. Классический ACL:
                         один список сверху вниз, а не набор весов, которые никто
                         не может сложить в голове.
  3. Политика по kind  — если не совпало ни одно правило.
  4. Лимиты            — проверяются ВСЕГДА, даже если правило сказало «разрешить».
                         Иначе правило «переводы Алёне разрешены» тихо съедало бы
                         дневной потолок, ради которого лимиты и заводят. Правило
                         может явно попросить обойти лимиты — флагом `skip_limits`.

Результаты складываются по строгости: deny > hitl > allow. Два источника,
сказавшие разное, не спорят — берётся более строгий, и в причине остаются оба.
"""
from __future__ import annotations

import fnmatch
import json
import re
import time

from . import db

ALLOW, DENY, HITL = "allow", "deny", "hitl"
SEVERITY = {ALLOW: 0, HITL: 1, DENY: 2}

# Статусы запросов, которые считаются «деньги ушли или могли уйти».
# Именно по ним считаются лимиты: отклонённый и провалившийся вызов потолок
# не расходует, иначе одна сетевая ошибка съедала бы дневной лимит.
COUNTED_STATUSES = ("allowed", "executed", "unknown")


class Decision:
    def __init__(self, action: str, reason: str = "", rule_id=None, rule_name: str = "",
                 hitl_mode: str = ""):
        self.action = action
        self.reasons: list[str] = [reason] if reason else []
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.hitl_mode = hitl_mode

    def merge(self, other: "Decision") -> "Decision":
        """Строгое побеждает; причины копятся."""
        if SEVERITY[other.action] > SEVERITY[self.action]:
            keep_reasons = self.reasons + other.reasons
            other.reasons = keep_reasons
            if not other.rule_name:
                other.rule_name, other.rule_id = self.rule_name, self.rule_id
            # Сценарий подтверждения задан правилом и не должен теряться от того,
            # что решение ужесточили лимит или квота.
            if not other.hitl_mode:
                other.hitl_mode = self.hitl_mode
            return other
        self.reasons += other.reasons
        return self

    @property
    def reason(self) -> str:
        return "; ".join(r for r in self.reasons if r)

    def __repr__(self) -> str:  # pragma: no cover - для отладки
        return f"<Decision {self.action}: {self.reason}>"


# ── списки ───────────────────────────────────────────────────────────────────

def _entry_matches(entry: dict, value: str) -> bool:
    kind = (entry.get("match") or "exact").lower()
    pattern = str(entry.get("value") or "")
    if not pattern:
        return False
    haystack = str(value or "")
    if kind == "exact":
        return haystack.strip().lower() == pattern.strip().lower()
    if kind == "substring":
        return pattern.lower() in haystack.lower()
    if kind == "prefix":
        return haystack.lower().startswith(pattern.lower())
    if kind == "regex":
        try:
            return re.search(pattern, haystack) is not None
        except re.error:
            # Сломанная регулярка НЕ совпадает — но и не роняет разбор. Правило,
            # падающее с 500, оставило бы систему без решения вообще.
            return False
    return False


def list_contains(list_ref, value: str) -> bool:
    row = None
    try:
        row = db.one("SELECT entries_json FROM lists WHERE id=?", (int(list_ref),))
    except (TypeError, ValueError):
        row = db.one("SELECT entries_json FROM lists WHERE name=?", (str(list_ref),))
    if row is None:
        return False
    entries = db.jload(row["entries_json"], [])
    return any(_entry_matches(e, value) for e in entries if isinstance(e, dict))


# ── условия ──────────────────────────────────────────────────────────────────

def _as_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def eval_condition(cond: dict, facets: dict) -> bool:
    field = cond.get("field") or "any"
    op = (cond.get("op") or "eq").lower()
    expected = cond.get("value")
    actual = facets.get(field)

    if op == "is_empty":
        return actual in (None, "", 0)
    if op == "not_empty":
        return actual not in (None, "", 0)

    if op in ("gt", "gte", "lt", "lte"):
        left, right = _as_float(actual), _as_float(expected)
        # Сравнение сумм там, где суммы нет (например, у чекаута не передали
        # expected_sum), НЕ совпадает: правило «больше 5000» не должно молча
        # пропускать вызов, в котором сумма вообще не видна. Ловить такое —
        # работа отдельного правила `amount is_empty`, и оно есть в сиде.
        if left is None or right is None:
            return False
        return {"gt": left > right, "gte": left >= right,
                "lt": left < right, "lte": left <= right}[op]

    text = "" if actual is None else str(actual)
    exp_text = "" if expected is None else str(expected)

    if op == "eq":
        left, right = _as_float(actual), _as_float(expected)
        if left is not None and right is not None:
            return left == right
        return text.strip().lower() == exp_text.strip().lower()
    if op == "ne":
        return not eval_condition({**cond, "op": "eq"}, facets)
    if op == "contains":
        return exp_text.lower() in text.lower()
    if op == "not_contains":
        return exp_text.lower() not in text.lower()
    if op == "starts_with":
        return text.lower().startswith(exp_text.lower())
    if op == "ends_with":
        return text.lower().endswith(exp_text.lower())
    if op == "regex":
        try:
            return re.search(exp_text, text) is not None
        except re.error:
            return False
    if op == "not_regex":
        try:
            return re.search(exp_text, text) is None
        except re.error:
            return False
    if op in ("in", "not_in"):
        items = expected if isinstance(expected, list) else str(expected or "").split(",")
        hit = any(text.strip().lower() == str(i).strip().lower() for i in items)
        return hit if op == "in" else not hit
    if op in ("in_list", "not_in_list"):
        hit = list_contains(expected, text)
        return hit if op == "in_list" else not hit
    return False


def match_block(block: dict, facets: dict) -> bool:
    """Совпал ли фильтр (используется и правилами, и лимитами)."""
    block = block or {}

    tools = [t for t in (block.get("tools") or []) if t]
    if tools and not any(fnmatch.fnmatch(facets.get("tool", ""), pat) for pat in tools):
        return False

    kinds = [k for k in (block.get("kinds") or []) if k]
    if kinds and facets.get("kind") not in kinds:
        return False

    cats = [c for c in (block.get("categories") or []) if c]
    if cats and facets.get("category") not in cats:
        return False

    conds = [c for c in (block.get("conditions") or []) if isinstance(c, dict) and c.get("field")]
    if not conds:
        return True
    mode = (block.get("conditions_mode") or "all").lower()
    results = [eval_condition(c, facets) for c in conds]
    return all(results) if mode == "all" else any(results)


# ── окна лимитов ─────────────────────────────────────────────────────────────

def window_start(window: str, now: float | None = None) -> float:
    """Границы календарные, а не скользящие: «дневной лимит» в голове у человека
    обнуляется в полночь, а не через 24 часа после первой траты."""
    now = now if now is not None else time.time()
    lt = time.localtime(now)
    if window == "hour":
        return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, lt.tm_hour, 0, 0,
                            lt.tm_wday, lt.tm_yday, -1))
    midnight = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0,
                            lt.tm_wday, lt.tm_yday, -1))
    if window == "day":
        return midnight
    if window == "week":
        return midnight - lt.tm_wday * 86400
    if window == "month":
        return time.mktime((lt.tm_year, lt.tm_mon, 1, 0, 0, 0, 0, 0, -1))
    return 0.0


def _spent(limit_row, facets: dict, now: float) -> tuple[float, int]:
    """Сколько уже потрачено и сколько операций сделано в окне этого лимита."""
    block = db.jload(limit_row["match_json"], {})
    since = window_start(limit_row["window"], now)
    placeholders = ",".join("?" for _ in COUNTED_STATUSES)
    rows = db.rows(
        f"SELECT amount, facets_json FROM requests "
        f"WHERE ts >= ? AND status IN ({placeholders})",
        (since, *COUNTED_STATUSES),
    )
    total, count = 0.0, 0
    for row in rows:
        past = db.jload(row["facets_json"], {})
        if not match_block(block, past):
            continue
        count += 1
        total += float(row["amount"] or 0)
    return total, count


def rule_usage(rule_id, window: str, now: float | None = None) -> tuple[int, float]:
    """Сколько раз и на какую сумму ЭТО правило уже пропустило в текущем окне.

    Считается по rule_id, а не пересчётом фильтра по истории: вопрос человека
    звучит как «сколько раз сегодня сработало это правило», и ответ на него не
    должен меняться от того, что правило потом отредактировали.

    Операции, подтверждённые человеком, сюда НЕ попадают: у них rule_id пуст.
    Так и надо — квота нормирует то, что проходит БЕЗ подтверждения."""
    if not rule_id or not window:
        return 0, 0.0
    now = now if now is not None else time.time()
    since = window_start(window, now)
    placeholders = ",".join("?" for _ in COUNTED_STATUSES)
    row = db.one(
        f"SELECT COUNT(*) c, COALESCE(SUM(amount), 0) s FROM requests "
        f"WHERE rule_id=? AND ts >= ? AND status IN ({placeholders})",
        (rule_id, since, *COUNTED_STATUSES))
    return (row["c"] if row else 0), float(row["s"] if row else 0.0)


_WINDOW_RU = {"hour": "час", "day": "сутки", "week": "неделю", "month": "месяц"}


def check_quota(row, facets: dict, now: float | None = None) -> Decision:
    """Квота разрешающего правила. Пустое окно — квоты нет."""
    window = (row["quota_window"] or "").strip() if "quota_window" in row.keys() else ""
    if not window:
        return Decision(ALLOW)
    action = row["quota_on_exceed"] if row["quota_on_exceed"] in SEVERITY else HITL
    used_count, used_amount = rule_usage(row["id"], window, now)
    amount = float(facets.get("amount") or 0)
    win = _WINDOW_RU.get(window, window)
    decision = Decision(ALLOW)

    max_count = row["quota_max_count"]
    if max_count is not None and used_count + 1 > int(max_count):
        decision = decision.merge(Decision(
            action,
            f"без подтверждения по правилу «{row['name']}» можно {int(max_count)} раз "
            f"за {win}, это уже {used_count + 1}-й"))
    max_amount = row["quota_max_amount"]
    if max_amount is not None and used_amount + amount > float(max_amount):
        decision = decision.merge(Decision(
            action,
            f"без подтверждения по правилу «{row['name']}» можно {float(max_amount):.2f} ₽ "
            f"за {win}, уже потрачено {used_amount:.2f} ₽ и просят ещё {amount:.2f} ₽"))
    return decision


def check_limits(facets: dict, now: float | None = None) -> Decision:
    now = now if now is not None else time.time()
    decision = Decision(ALLOW)
    amount = float(facets.get("amount") or 0)
    for row in db.rows("SELECT * FROM limits WHERE enabled=1 ORDER BY id"):
        block = db.jload(row["match_json"], {})
        if not match_block(block, facets):
            continue
        action = row["on_exceed"] if row["on_exceed"] in SEVERITY else DENY

        if row["window"] == "tx":
            # Потолок одной операции. Считать историю незачем.
            if row["max_amount"] is not None and amount > float(row["max_amount"]):
                decision = decision.merge(Decision(
                    action,
                    f"лимит «{row['name']}»: {amount:.2f} ₽ за раз при потолке "
                    f"{float(row['max_amount']):.2f} ₽"))
            continue

        spent, count = _spent(row, facets, now)
        win = {"hour": "час", "day": "сутки", "week": "неделю", "month": "месяц"}.get(
            row["window"], row["window"])
        if row["max_amount"] is not None and spent + amount > float(row["max_amount"]):
            decision = decision.merge(Decision(
                action,
                f"лимит «{row['name']}»: за {win} уже {spent:.2f} ₽, "
                f"эта операция {amount:.2f} ₽, потолок {float(row['max_amount']):.2f} ₽"))
        if row["max_count"] is not None and count + 1 > int(row["max_count"]):
            decision = decision.merge(Decision(
                action,
                f"лимит «{row['name']}»: за {win} уже {count} операций "
                f"при потолке {int(row['max_count'])}"))
    return decision


# ── режимы тулов ─────────────────────────────────────────────────────────────

def tool_mode(tool: str) -> str:
    row = db.one("SELECT mode FROM tool_modes WHERE tool=?", (tool,))
    return row["mode"] if row else "on"


def hidden_tools() -> list[str]:
    return [r["tool"] for r in db.rows("SELECT tool FROM tool_modes WHERE mode='hidden'")]


# ── основной разбор ──────────────────────────────────────────────────────────

def check_requisites(facets: dict) -> Decision:
    """Маршрут получателя должен быть тем, что вернул БАНК, а не моделью.

    `bankMemberId` и `pointerLinkId` нельзя вывести из номера телефона — их
    отдаёт только `transfer_sbp_resolve`. Если у модели не получилось их
    получить (например, банк ответил «слишком много попыток»), она склонна
    подставить правдоподобные цифры и пойти платить. Это уже происходило:
    перевод ушёл по выдуманному bankMemberId и получил 403.

    Ни одно правило это не ловит: с точки зрения фильтров такой вызов выглядит
    обычным переводом обычному получателю. Поэтому проверка отдельная, идёт
    раньше правил и разрешающим правилом не отменяется.

    Пустые реквизиты — нормальный и более безопасный путь: клиент сам сходит
    в резолв и возьмёт дефолтный банк.
    """
    if db.get_setting("require_resolved_requisites", "1") != "1":
        return Decision(ALLOW)
    if facets.get("tool") != "transfer":
        return Decision(ALLOW)
    bmi = str(facets.get("bank_member_id") or "").strip()
    plid = str(facets.get("pointer_link_id") or "").strip()
    if not bmi and not plid:
        return Decision(ALLOW)

    recipient = str(facets.get("recipient") or "")
    rows = db.rows("SELECT bank_member_id, pointer_link_id, bank_name FROM "
                   "resolved_requisites WHERE recipient=?", (recipient,))
    if not rows:
        return Decision(DENY, (
            "переданы реквизиты СБП, которых банк не возвращал: для этого получателя "
            "transfer_sbp_resolve в журнале нет вообще. Вызови его и возьми "
            "bankMemberId/pointerLinkId из ответа — или не передавай их совсем, "
            "тогда банк подберёт получателя сам"))
    for row in rows:
        if bmi and bmi != row["bank_member_id"]:
            continue
        if plid and plid != row["pointer_link_id"]:
            continue
        return Decision(ALLOW)
    known = ", ".join(f"{r['bank_member_id']}/{r['pointer_link_id']}"
                      f"{(' (' + r['bank_name'] + ')') if r['bank_name'] else ''}"
                      for r in rows)
    return Decision(DENY, (
        f"реквизиты СБП не совпадают с тем, что вернул банк: прислано "
        f"{bmi or '—'}/{plid or '—'}, а резолв давал {known}. Не подставляй эти "
        f"идентификаторы сам — вызови transfer_sbp_resolve заново"))


def evaluate(facets: dict, now: float | None = None) -> Decision:
    tool = facets.get("tool", "")
    mode = tool_mode(tool)
    if mode in ("blocked", "hidden"):
        return Decision(DENY, f"тул «{tool}» выключен в зоне видимости агента")

    # Раньше правил и вне их власти: это не политика владельца, а проверка на то,
    # что агент не выдумал платёжные реквизиты.
    invented = check_requisites(facets)
    if invented.action != ALLOW:
        return invented

    matched: Decision | None = None
    for row in db.rows("SELECT * FROM rules WHERE enabled=1 ORDER BY priority, id"):
        block = db.jload(row["match_json"], {})
        if not match_block(block, facets):
            continue
        action = row["action"] if row["action"] in SEVERITY else HITL
        why = row["reason"] or f"правило «{row['name']}»"
        matched = Decision(action, why, row["id"], row["name"], row["hitl_mode"] or "")
        # Квота имеет смысл только у разрешающего правила: «запрещать не больше
        # трёх раз в сутки» — это не политика, а опечатка.
        if action == ALLOW:
            matched = matched.merge(check_quota(row, facets, now))
        skip_limits = bool(row["skip_limits"])
        break
    else:
        skip_limits = False

    if matched is None:
        kind = facets.get("kind", "money")
        fallback = db.get_setting(f"default_{kind}", HITL)
        fallback = fallback if fallback in SEVERITY else HITL
        matched = Decision(fallback, f"правило не найдено, политика по умолчанию для «{kind}»")

    if skip_limits:
        matched.reasons.append("лимиты пропущены по флагу правила")
        return matched
    return matched.merge(check_limits(facets, now))
