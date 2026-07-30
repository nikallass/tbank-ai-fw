"""Шлюз: ни один тул не доходит до банка, не спросив фаервол.

ПОЧЕМУ ЭТО ОДИН МОДУЛЬ И ОДНА ВРЕЗКА.
В `server.py` все туллы регистрируются через единственную обёртку `_traced_tool`.
Значит, и проверка ставится в одном месте, а не в 61 функции. Список «какие туллы
проверять» существовать не должен вообще: тул, который забыли в него внести, — это
ровно тот тул, через который однажды уйдут деньги. Здесь проверяются ВСЕ, а
исключения перечислены явно и их три (`_BYPASS`), все — про сам фаервол.

ЧТО ПРОИСХОДИТ ВОКРУГ ВЫЗОВА.
    authorize → (allow | deny | hitl) → сам вызов → result
`result` возвращает ответ тула, уже пропущенный через маски фаервола: номер карты
и CVV не должны попадать в контекст модели только потому, что вызов был разрешён.

ЧТО ПРОИСХОДИТ, ЕСЛИ ФАЕРВОЛ НЕ ОТВЕЧАЕТ.
По умолчанию — отказ (`closed`). Это неудобно и это намеренно: смысл всей затеи в
том, что банковский тул не выполняется без разрешения, и «фаервол упал» не может
означать «значит, можно всё». `TBANK_FIREWALL_FAILMODE=read-open` разрешает при
недоступном фаерволе только чтение, `open` — всё (для отладки, не для денег).
"""
from __future__ import annotations

import asyncio
import functools
import inspect
import json
import os
import sys
import time
import urllib.error
import urllib.request

FIREWALL_URL = os.environ.get("TBANK_FIREWALL_URL", "http://127.0.0.1:8080").rstrip("/")
FAIL_MODE = os.environ.get("TBANK_FIREWALL_FAILMODE", "closed").lower()
TIMEOUT = float(os.environ.get("TBANK_FIREWALL_TIMEOUT", "8"))
AGENT = os.environ.get("TBANK_AGENT_NAME", "mcp-client")
ENABLED = os.environ.get("TBANK_FIREWALL", "1") not in ("0", "false", "no", "")

# Туллы самого фаервола: их нельзя проверять фаерволом, иначе агент, которому
# отказали, не сможет даже узнать статус своего подтверждения.
_BYPASS = {"firewall_status", "firewall_pending", "firewall_policy", "firewall_choice"}

# Одна на процесс — сервер MCP запускается на сессию агента, и это самое близкое
# к «одному прогону», что есть без изобретения протокола.
SESSION_ID = os.environ.get("TBANK_SESSION_ID") or hex(int(time.time() * 1000))[-8:]

_OFFLINE_NOTE = (
    "Фаервол Bank AI Firewall недоступен ({url}): {err}.\n"
    "Банковские туллы работают только через него. Проверьте, что контейнер запущен "
    "(`docker compose up -d`), и повторите."
)


# Мимо системного прокси. Фаервол живёт на этой же машине, и HTTP_PROXY из
# окружения отправлял бы запрос про перевод денег на чужой хост — который в лучшем
# случае вернёт 502 (так это и обнаружилось), а в худшем увидит аргументы вызова.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _post(path: str, payload: dict) -> dict:
    req = urllib.request.Request(
        FIREWALL_URL + path,
        data=json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST")
    with _OPENER.open(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get(path: str, timeout: float | None = None) -> dict:
    req = urllib.request.Request(FIREWALL_URL + path, method="GET")
    with _OPENER.open(req, timeout=timeout or TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _offline_decision(tool: str, kind: str, err: Exception) -> dict:
    note = _OFFLINE_NOTE.format(url=FIREWALL_URL, err=err)
    print(f"[tbank-firewall] {tool}: {err}", file=sys.stderr)
    if FAIL_MODE == "open" or (FAIL_MODE == "read-open" and kind == "read"):
        print(f"[tbank-firewall] failmode={FAIL_MODE}: пропускаю {tool} без проверки",
              file=sys.stderr)
        return {"decision": "allow", "request_id": "", "offline": True}
    return {"decision": "deny", "request_id": "", "offline": True,
            "message": "🚫 " + note}


def authorize(tool: str, kind: str, args: dict) -> dict:
    try:
        return _post("/api/v1/authorize", {
            "tool": tool, "kind": kind, "args": args,
            "agent": AGENT, "session": SESSION_ID})
    except (urllib.error.URLError, OSError, ValueError) as e:
        return _offline_decision(tool, kind, e)


def report(request_id: str, status: str, output: str, ms: int) -> str:
    """Отдать фаерволу исход и получить ответ, пропущенный через маски.

    Никогда не роняет вызов: если фаервол отвалился уже ПОСЛЕ того, как банк
    провёл операцию, потерять ответ — худшее, что можно сделать."""
    if not request_id:
        return output
    try:
        res = _post(f"/api/v1/requests/{request_id}/result",
                    {"status": status, "output": output or "", "ms": ms})
        return res.get("output", output)
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"[tbank-firewall] не удалось записать результат {request_id}: {e}",
              file=sys.stderr)
        return output


def request_state(request_id: str) -> dict:
    return _get(f"/api/v1/requests/{request_id}")


def await_decision(request_id: str, wait_sec: int = 0) -> dict:
    """Состояние запроса, при wait_sec > 0 — дождавшись решения человека.

    Длинный опрос вместо мгновенного ответа существует ради одной вещи: чтобы
    операция доводилась до конца в ОДНОМ ходе агента. Иначе цепочка рвётся —
    агент отдаёт ссылку, человек жмёт кнопку, и продолжить некому: у MCP нет
    способа разбудить чат, а агент без хода пользователя не проснётся сам.

    Опрос локальный (localhost), поэтому шаг маленький: решение подхватывается
    почти сразу после нажатия."""
    state = request_state(request_id)
    if wait_sec <= 0 or state.get("hitl_state") != "pending":
        return state
    deadline = time.time() + wait_sec
    while time.time() < deadline:
        time.sleep(1.0)
        try:
            state = request_state(request_id)
        except (urllib.error.URLError, OSError, ValueError):
            continue                     # фаервол моргнул — ждём дальше
        if state.get("hitl_state") != "pending":
            return state
    return state


def pending() -> dict:
    return _get("/api/v1/pending")


def create_choice(phone: str, options: list, amount=None, from_account: str = "") -> dict:
    """Завести в фаерволе выбор банка. None, если фаервол недоступен.

    Кандидаты уходят туда не только ради кнопок: резолв случился ВНУТРИ клиента,
    мимо тула transfer_sbp_resolve, и без этой передачи фаервол про выданные
    реквизиты не знает — а потом сам же их отвергает как неизвестные."""
    try:
        return _post("/api/v1/choice", {
            "recipient": phone, "amount": amount, "from_account": from_account,
            "agent": AGENT, "candidates": options})
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"[tbank-firewall] выбор банка не заведён: {e}", file=sys.stderr)
        return {}


def await_choice(choice_id: str, wait_sec: int = 0) -> dict:
    """Состояние выбора, при wait_sec > 0 — дождавшись клика."""
    state = _get(f"/api/v1/choice/{choice_id}")
    if wait_sec <= 0 or state.get("state") != "pending":
        return state
    deadline = time.time() + wait_sec
    while time.time() < deadline:
        time.sleep(1.0)
        try:
            state = _get(f"/api/v1/choice/{choice_id}")
        except (urllib.error.URLError, OSError, ValueError):
            continue
        if state.get("state") != "pending":
            return state
    return state


def hidden_tools() -> set[str]:
    """Туллы, которых агент вообще не должен видеть. Спрашивается один раз при
    старте: список тулов отдаётся клиенту на хендшейке и позже не меняется."""
    if not ENABLED:
        return set()
    try:
        return set(_get("/api/v1/visibility", timeout=3).get("hidden") or [])
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"[tbank-firewall] зона видимости недоступна, показываю все туллы: {e}",
              file=sys.stderr)
        return set()


# ── исход вызова ─────────────────────────────────────────────────────────────

# Строки, которыми туллы этой репы сообщают «запрос не прошёл, деньги на месте».
# Только они освобождают лимит. Всё остальное считается проведённым — ошибиться
# в эту сторону значит зря придержать потолок, ошибиться в другую — выпустить
# за суточный лимит платёж, который на самом деле прошёл.
_MONEY_SAFE_MARKERS = (
    "Перевод НЕ выполнен",
    "Платёж НЕ выполнен",
    "ЗАБЛОКИРОВАНО ФАЕРВОЛОМ",
)
_MONEY_UNKNOWN_MARKERS = ("ИСХОД НЕИЗВЕСТЕН",)


def _outcome(output) -> str:
    text = output if isinstance(output, str) else ""
    head = text[:400]
    if any(m in head for m in _MONEY_UNKNOWN_MARKERS):
        return "unknown"
    if any(m in head for m in _MONEY_SAFE_MARKERS):
        return "error"
    return "ok"


def _bind(fn, a, kw) -> dict:
    """Аргументы вызова, включая значения по умолчанию.

    Умолчания важны: правило про `reveal` у `card_requisites` или про пустой
    `expected_sum` у чекаута должно видеть то же, что увидит сам тул."""
    try:
        bound = inspect.signature(fn).bind_partial(*a, **kw)
        bound.apply_defaults()
        return dict(bound.arguments)
    except (TypeError, ValueError):
        return dict(kw)


def _wait_for_human(request_id: str, wait_sec: int) -> tuple[bool, str]:
    """Режим «ждёт»: опрашивать фаервол, пока человек не решит."""
    deadline = time.time() + max(wait_sec, 0)
    while time.time() < deadline:
        time.sleep(2)
        try:
            state = request_state(request_id)
        except (urllib.error.URLError, OSError, ValueError):
            continue
        if state.get("hitl_state") == "approved":
            return True, ""
        if state.get("hitl_state") in ("denied", "expired"):
            return False, (f"Владелец отклонил операцию ({state.get('hitl_state')})."
                           + (f" Комментарий: {state['note']}" if state.get("note") else ""))
    return False, ("Владелец не ответил за отведённое время. Операция НЕ выполнена. "
                   "Попроси пользователя открыть ссылку и повтори вызов.")


def wrap(fn, tool: str, kind: str):
    """Обернуть один тул проверкой фаервола."""
    if not ENABLED or tool in _BYPASS:
        return fn

    def _before(a, kw):
        args = _bind(fn, a, kw)
        decision = authorize(tool, kind, args)
        action = decision.get("decision", "deny")
        if action == "allow":
            return None, decision.get("request_id", "")
        if action == "deny":
            return decision.get("message") or "Заблокировано фаерволом.", ""
        # hitl
        hitl = decision.get("hitl") or {}
        if hitl.get("mode") == "wait":
            approved, why = _wait_for_human(decision.get("request_id", ""),
                                            int(hitl.get("wait_sec") or 120))
            if approved:
                return None, decision.get("request_id", "")
            return f"{decision.get('message', '')}\n\n{why}", ""
        return decision.get("message") or "Требуется подтверждение владельца.", ""

    if asyncio.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def awrapper(*a, **kw):
            refusal, req_id = await asyncio.to_thread(_before, a, kw)
            if refusal is not None:
                return refusal
            started = time.time()
            try:
                out = await fn(*a, **kw)
            except BaseException as e:
                await asyncio.to_thread(report, req_id, "error", f"{type(e).__name__}: {e}",
                                        int((time.time() - started) * 1000))
                raise
            return await asyncio.to_thread(report, req_id, _outcome(out), out,
                                           int((time.time() - started) * 1000))
        return awrapper

    @functools.wraps(fn)
    def swrapper(*a, **kw):
        refusal, req_id = _before(a, kw)
        if refusal is not None:
            return refusal
        started = time.time()
        try:
            out = fn(*a, **kw)
        except BaseException as e:
            report(req_id, "error", f"{type(e).__name__}: {e}",
                   int((time.time() - started) * 1000))
            raise
        return report(req_id, _outcome(out), out, int((time.time() - started) * 1000))

    return swrapper
