"""Bank AI Firewall. HTTP-морда: API для MCP и вебморда для человека.

ДВА ПОТРЕБИТЕЛЯ, ОДИН ИСТОЧНИК ПРАВДЫ.
  • MCP спрашивает `/api/v1/authorize` перед КАЖДЫМ вызовом тула и отдаёт
    результат в `/api/v1/requests/{id}/result` после. Между этими двумя точками
    фаервол видит всё, что агент делает с банком.
  • Человек открывает вебморду, правит правила и нажимает «подтвердить».

Аутентификации пока нет намеренно (см. README): сервис слушает 127.0.0.1 и
живёт на машине владельца. Прежде чем выставлять его наружу, нужен вход —
это первый пункт в списке доработок.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from . import catalog, db, facets as facets_mod, masking, policy, seed

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    if seed.seed_if_empty():
        print("[firewall] стартовая политика заведена")
    yield


app = FastAPI(title="Bank AI Firewall", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


# ── схемы ────────────────────────────────────────────────────────────────────

class AuthorizeIn(BaseModel):
    tool: str
    kind: str | None = None
    args: dict = Field(default_factory=dict)
    agent: str = ""
    session: str = ""


class ResultIn(BaseModel):
    status: str = "ok"          # ok | error | unknown | refused
    output: str = ""
    ms: int | None = None
    error: str = ""


# ── тексты для агента ────────────────────────────────────────────────────────

def _subject(facets: dict) -> str:
    """Одна строка «что именно происходит» — она же заголовок карточки в UI."""
    bits = [f"{catalog.title_of(facets['tool'])} ({facets['tool']})"]
    if facets.get("amount"):
        bits.append(f"{float(facets['amount']):.2f} ₽")
    if facets.get("recipient"):
        who = facets["recipient"]
        if facets.get("recipient_name"):
            who += f" ({facets['recipient_name']})"
        bits.append(f"→ {who}")
    if facets.get("org") and not facets.get("recipient"):
        bits.append(f"→ {facets['org']}")
    if facets.get("from_account"):
        bits.append(f"со счёта {facets['from_account']}")
    return " · ".join(bits)


def _deny_message(req_id: str, facets: dict, reason: str, base_url: str) -> str:
    # Последняя строка — не вежливость, а защита от цикла: агент, получивший
    # отказ, по умолчанию пробует ещё раз, и без явного «повтор не поможет»
    # он сожжёт на этом несколько попыток.
    return (
        f"🚫 ЗАБЛОКИРОВАНО ФАЕРВОЛОМ\n"
        f"Операция: {_subject(facets)}\n"
        f"Причина: {reason}\n"
        f"Запрос: {req_id} — {base_url}/requests/{req_id}\n"
        f"Повторять этот вызов бессмысленно: пока владелец не изменит правило, "
        f"ответ будет тем же. Сообщи пользователю причину отказа и ссылку."
    )


def _hitl_message(req_id: str, facets: dict, reason: str, base_url: str,
                  mode: str, ttl: int) -> str:
    url = f"{base_url}/hitl/{req_id}"
    head = (
        f"⏳ НУЖНО ПОДТВЕРЖДЕНИЕ ВЛАДЕЛЬЦА\n"
        f"Операция: {_subject(facets)}\n"
        f"Причина: {reason}\n"
        f"Подтвердить или отклонить: {url}\n"
        f"Ссылка действует {ttl // 60} мин."
    )
    if mode == "wait":
        return head + "\n(вызов ждёт решения; если время выйдет — операция не выполнится)"
    # Инструкция написана так, чтобы операция доводилась до конца в ОДНОМ ходе
    # агента. Раньше здесь было «жди и спроси статус» — агент послушно отдавал
    # ссылку и замолкал, а разбудить чат после нажатия кнопки некому: у MCP нет
    # обратного канала. Ожидание переехало внутрь firewall_status(wait_sec).
    return (
        head + "\n\nЧто делать дальше, ОДНИМ ходом и без остановки:\n"
        f"1. Покажи пользователю ссылку выше.\n"
        f"2. Сразу вызови firewall_status(\"{req_id}\", wait_sec=60) — этот вызов "
        f"САМ дождётся, пока владелец нажмёт кнопку, и вернётся с ответом. "
        f"Не жди хода пользователя и не заканчивай сообщение на этом шаге.\n"
        f"3. Вернулось approved — повтори ЭТОТ ЖЕ вызов с ТЕМИ ЖЕ аргументами, "
        f"он пройдёт без вопросов. Вернулось pending — время вышло, позови "
        f"firewall_status ещё раз. denied или expired — операция отменена.\n"
        f"Аргументы не подменяй: подтверждение выдано ровно на эту операцию."
    )


# ── авторизация вызова ───────────────────────────────────────────────────────

def _insert_request(req_id: str, payload: AuthorizeIn, facets: dict, sig: str,
                    decision: str, status: str, rule_id, rule_name: str,
                    reason: str, now: float) -> None:
    db.run(
        "INSERT INTO requests(id, ts, agent, session, tool, kind, category, args_json, "
        "facets_json, amount, recipient, org, card, from_account, decision, status, "
        "rule_id, rule_name, reason, sig) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (req_id, now, payload.agent, payload.session, payload.tool, facets["kind"],
         facets["category"],
         json.dumps(facets_mod.scrub_args(payload.args), ensure_ascii=False, default=str),
         json.dumps(facets, ensure_ascii=False, default=str),
         facets.get("amount"), facets.get("recipient", ""), facets.get("org", ""),
         facets.get("card", ""), facets.get("from_account", ""),
         decision, status, rule_id, rule_name, reason, sig),
    )


@app.post("/api/v1/authorize")
def authorize(payload: AuthorizeIn) -> dict:
    now = time.time()
    settings = db.settings()
    base_url = settings.get("base_url", "http://localhost:8080").rstrip("/")
    facets = facets_mod.extract(payload.tool, payload.args, payload.agent)
    sig = facets_mod.signature(payload.tool, payload.args)
    req_id = "req_" + uuid.uuid4().hex[:12]

    # 1. Этот вызов уже подтверждён человеком? Одноразово и только на тот же
    #    отпечаток: подтверждали 100 ₽ Алёне — 100 ₽ Алёне и пройдёт, 10 000 ₽
    #    кому-то другому пойдут спрашивать заново.
    approved = db.one(
        "SELECT * FROM hitl WHERE sig=? AND state='approved' AND consumed_at IS NULL "
        "AND expires_at > ? ORDER BY decided_at DESC LIMIT 1", (sig, now))
    if approved is not None:
        db.run("UPDATE hitl SET consumed_at=? WHERE request_id=?", (now, approved["request_id"]))
        db.run("UPDATE requests SET status='superseded' WHERE id=? AND status='pending'",
               (approved["request_id"],))
        when = time.strftime("%H:%M", time.localtime(approved["decided_at"] or now))
        reason = f"подтверждено владельцем в {when} (запрос {approved['request_id']})"
        _insert_request(req_id, payload, facets, sig, policy.ALLOW, "allowed",
                        None, "подтверждение человеком", reason, now)
        return {"request_id": req_id, "decision": "allow", "reason": reason,
                "rule": None, "message": ""}

    # 2. Такой же вызов уже висит на подтверждении? Агент в async-режиме честно
    #    приходит повторно, и без этой ветки каждый его заход плодил бы владельцу
    #    новую карточку на ту же операцию — а из десяти одинаковых карточек
    #    человек рано или поздно подтвердит не глядя.
    waiting = db.one(
        "SELECT * FROM hitl WHERE sig=? AND state='pending' AND expires_at > ? "
        "ORDER BY created_at DESC LIMIT 1", (sig, now))
    if waiting is not None:
        row = db.one("SELECT * FROM requests WHERE id=?", (waiting["request_id"],))
        left = int(waiting["expires_at"] - now)
        return {
            "request_id": waiting["request_id"], "decision": "hitl",
            "reason": (row["reason"] if row else "") or "ожидает подтверждения",
            "rule": row["rule_name"] if row else "",
            "hitl": {"mode": waiting["mode"],
                     "url": f"{base_url}/hitl/{waiting['request_id']}",
                     "ttl_sec": left, "wait_sec": int(settings.get("hitl_wait_sec", "120"))},
            "message": _hitl_message(waiting["request_id"], facets,
                                     (row["reason"] if row else ""), base_url,
                                     waiting["mode"], max(left, 0)),
        }

    decision = policy.evaluate(facets, now)

    if decision.action == policy.ALLOW:
        _insert_request(req_id, payload, facets, sig, "allow", "allowed",
                        decision.rule_id, decision.rule_name, decision.reason, now)
        return {"request_id": req_id, "decision": "allow", "reason": decision.reason,
                "rule": decision.rule_name, "message": ""}

    if decision.action == policy.DENY:
        _insert_request(req_id, payload, facets, sig, "deny", "denied",
                        decision.rule_id, decision.rule_name, decision.reason, now)
        return {"request_id": req_id, "decision": "deny", "reason": decision.reason,
                "rule": decision.rule_name,
                "message": _deny_message(req_id, facets, decision.reason, base_url)}

    # HITL
    mode = decision.hitl_mode or settings.get("hitl_mode", "async")
    ttl = int(settings.get("hitl_ttl_sec", "900"))
    wait_sec = int(settings.get("hitl_wait_sec", "120"))
    _insert_request(req_id, payload, facets, sig, "hitl", "pending",
                    decision.rule_id, decision.rule_name, decision.reason, now)
    db.run("INSERT INTO hitl(request_id, created_at, expires_at, state, mode, sig) "
           "VALUES (?,?,?,?,?,?)", (req_id, now, now + ttl, "pending", mode, sig))
    return {
        "request_id": req_id, "decision": "hitl", "reason": decision.reason,
        "rule": decision.rule_name,
        "hitl": {"mode": mode, "url": f"{base_url}/hitl/{req_id}",
                 "ttl_sec": ttl, "wait_sec": wait_sec},
        "message": _hitl_message(req_id, facets, decision.reason, base_url, mode, ttl),
    }


@app.get("/api/v1/requests/{req_id}")
def request_state(req_id: str) -> dict:
    row = db.one("SELECT * FROM requests WHERE id=?", (req_id,))
    if row is None:
        raise HTTPException(404, "нет такого запроса")
    hitl = db.one("SELECT * FROM hitl WHERE request_id=?", (req_id,))
    state = row["status"]
    hitl_state = ""
    note = ""
    if hitl is not None:
        hitl_state = hitl["state"]
        note = hitl["note"] or ""
        if hitl_state == "pending" and hitl["expires_at"] < time.time():
            db.run("UPDATE hitl SET state='expired' WHERE request_id=?", (req_id,))
            db.run("UPDATE requests SET status='expired' WHERE id=?", (req_id,))
            hitl_state, state = "expired", "expired"
    return {
        "request_id": req_id, "decision": row["decision"], "status": state,
        "hitl_state": hitl_state, "note": note, "reason": row["reason"],
        "tool": row["tool"], "amount": row["amount"],
    }


_RE_PROVIDER_FIELDS = re.compile(r"providerFields:\s*(\{[^\n]*\})")


def _remember_requisites(row, output: str) -> int:
    """Запомнить маршруты СБП, которые банк вернул на transfer_sbp_resolve.

    Это не кэш: отсюда ничего не подставляется в платёж. Единственный потребитель —
    policy.check_requisites, который сверяет присланное агентом с тем, что банк
    действительно называл. Разбирается ответ тула, а не запрос: то, что агент
    ПРОСИЛ, доверия не заслуживает по определению.
    """
    saved = 0
    for match in _RE_PROVIDER_FIELDS.finditer(output or ""):
        try:
            fields = json.loads(match.group(1))
        except ValueError:
            continue
        if not isinstance(fields, dict):
            continue
        bmi = str(fields.get("bankMemberId") or "").strip()
        plid = str(fields.get("pointerLinkId") or "").strip()
        if not bmi and not plid:
            continue
        # Получателя берём из фактов запроса, а не из ответа: он уже нормализован
        # тем же способом, каким будет нормализован телефон в переводе.
        recipient = row["recipient"] or facets_mod.norm_phone(
            str(fields.get("pointer") or ""))
        if not recipient:
            continue
        db.run(
            "INSERT INTO resolved_requisites(recipient, bank_member_id, "
            "pointer_link_id, bank_name, masked_fio, ts) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(recipient, bank_member_id, pointer_link_id) "
            "DO UPDATE SET ts=excluded.ts, masked_fio=excluded.masked_fio",
            (recipient, bmi, plid, "", str(fields.get("maskedFIO") or ""), time.time()))
        saved += 1
    return saved


@app.post("/api/v1/requests/{req_id}/result")
def request_result(req_id: str, payload: ResultIn) -> dict:
    row = db.one("SELECT * FROM requests WHERE id=?", (req_id,))
    if row is None:
        raise HTTPException(404, "нет такого запроса")
    if row["tool"] == "transfer_sbp_resolve" and payload.status == "ok":
        _remember_requisites(row, payload.output or "")
    status_map = {"ok": "executed", "error": "failed",
                  "unknown": "unknown", "refused": "failed"}
    new_status = status_map.get(payload.status, "executed")
    masked = masking.apply(payload.output or "")
    head = (masked.strip().splitlines() or [""])[0][:300]
    db.run(
        "UPDATE requests SET result_ts=?, result_status=?, ms=?, output_head=?, status=? "
        "WHERE id=?",
        (time.time(), payload.status, payload.ms, head or (payload.error or "")[:300],
         new_status, req_id))
    return {"output": masked}


class ChoiceIn(BaseModel):
    recipient: str = ""
    amount: float | None = None
    from_account: str = ""
    agent: str = ""
    candidates: list[dict] = Field(default_factory=list)


class RequisitesIn(BaseModel):
    recipient: str = ""
    candidates: list[dict] = Field(default_factory=list)


def _store_requisites(recipient: str, candidates: list) -> int:
    now = time.time()
    saved = 0
    for c in candidates:
        bmi = str(c.get("bank_member_id") or "").strip()
        plid = str(c.get("pointer_link_id") or "").strip()
        if not recipient or not (bmi or plid):
            continue
        db.run(
            "INSERT INTO resolved_requisites(recipient, bank_member_id, "
            "pointer_link_id, bank_name, masked_fio, ts) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(recipient, bank_member_id, pointer_link_id) "
            "DO UPDATE SET ts=excluded.ts, bank_name=excluded.bank_name, "
            "masked_fio=excluded.masked_fio",
            (recipient, bmi, plid, str(c.get("bank_name") or ""),
             str(c.get("masked_fio") or ""), now))
        saved += 1
    return saved


@app.post("/api/v1/requisites")
def requisites_remember(payload: RequisitesIn) -> dict:
    """Запомнить, что банк вернул по номеру. Пишет только MCP, и только то, что
    пришло ОТ БАНКА: резолв внутри клиента идёт мимо тулов, и без этой ручки
    фаервол отвергает реквизиты, которые сам же MCP выдал агенту."""
    recipient = facets_mod.norm_phone(payload.recipient) if payload.recipient else ""
    return {"ok": True, "saved": _store_requisites(recipient, payload.candidates)}


@app.post("/api/v1/choice")
def choice_create(payload: ChoiceIn) -> dict:
    """Завести выбор банка получателя — человек решит кликом.

    Кандидаты приходят из резолва, который MCP сделал ВНУТРИ transfer(), мимо
    тула `transfer_sbp_resolve`. Поэтому здесь же они запоминаются как выданные
    банком: иначе фаервол про них не знает и потом сам отвергает реквизиты,
    которые сам же и предложил выбрать."""
    now = time.time()
    ttl = int(db.get_setting("hitl_ttl_sec", "900"))
    cid = "chc_" + uuid.uuid4().hex[:12]
    recipient = facets_mod.norm_phone(payload.recipient) if payload.recipient else ""
    db.run(
        "INSERT INTO choices(id, created_at, expires_at, state, recipient, amount, "
        "from_account, agent, candidates_json) VALUES (?,?,?,?,?,?,?,?,?)",
        (cid, now, now + ttl, "pending", recipient, payload.amount,
         payload.from_account, payload.agent,
         json.dumps(payload.candidates, ensure_ascii=False)))
    _store_requisites(recipient, payload.candidates)
    base_url = db.get_setting("base_url").rstrip("/")
    return {"choice_id": cid, "url": f"{base_url}/choice/{cid}", "ttl_sec": ttl}


@app.get("/api/v1/choice/{choice_id}")
def choice_state(choice_id: str) -> dict:
    row = db.one("SELECT * FROM choices WHERE id=?", (choice_id,))
    if row is None:
        raise HTTPException(404, "нет такого выбора")
    state = row["state"]
    if state == "pending" and row["expires_at"] < time.time():
        db.run("UPDATE choices SET state='expired' WHERE id=?", (choice_id,))
        state = "expired"
    return {"choice_id": choice_id, "state": state,
            "recipient": row["recipient"], "amount": row["amount"],
            "chosen": db.jload(row["chosen_json"], None),
            "candidates": db.jload(row["candidates_json"], [])}


@app.post("/api/v1/choice/{choice_id}/pick")
def choice_pick(choice_id: str, payload: dict = Body(...)) -> dict:
    row = db.one("SELECT * FROM choices WHERE id=?", (choice_id,))
    if row is None:
        raise HTTPException(404, "нет такого выбора")
    if row["state"] != "pending":
        return {"ok": False, "state": row["state"], "error": "выбор уже сделан"}
    now = time.time()
    if row["expires_at"] < now:
        db.run("UPDATE choices SET state='expired' WHERE id=?", (choice_id,))
        return {"ok": False, "state": "expired", "error": "срок выбора истёк"}
    if payload.get("cancel"):
        db.run("UPDATE choices SET state='cancelled', decided_at=? WHERE id=?",
               (now, choice_id))
        return {"ok": True, "state": "cancelled"}
    cands = db.jload(row["candidates_json"], [])
    try:
        chosen = cands[int(payload.get("index"))]
    except (TypeError, ValueError, IndexError):
        raise HTTPException(400, "неверный номер варианта")
    if not chosen.get("supported", True):
        return {"ok": False, "state": "pending",
                "error": "этот банк через MCP недоступен — выберите другой"}
    db.run("UPDATE choices SET state='picked', chosen_json=?, decided_at=? WHERE id=?",
           (json.dumps(chosen, ensure_ascii=False), now, choice_id))
    return {"ok": True, "state": "picked", "chosen": chosen}


@app.get("/choice/{choice_id}", response_class=HTMLResponse)
def ui_choice(request: Request, choice_id: str):
    row = db.one("SELECT * FROM choices WHERE id=?", (choice_id,))
    if row is None:
        raise HTTPException(404, "нет такого выбора")
    return _page(request, "choice", row=dict(row),
                 candidates=db.jload(row["candidates_json"], []),
                 chosen=db.jload(row["chosen_json"], None))


@app.get("/api/v1/visibility")
def visibility() -> dict:
    modes = {r["tool"]: r["mode"] for r in db.rows("SELECT tool, mode FROM tool_modes")}
    return {
        "hidden": [t for t, m in modes.items() if m == "hidden"],
        "blocked": [t for t, m in modes.items() if m == "blocked"],
        "modes": modes,
    }


@app.get("/api/v1/pending")
def pending() -> dict:
    now = time.time()
    rows = db.rows(
        "SELECT r.id, r.ts, r.tool, r.amount, r.recipient, r.reason, h.expires_at "
        "FROM requests r JOIN hitl h ON h.request_id=r.id "
        "WHERE h.state='pending' AND h.expires_at > ? ORDER BY r.ts DESC", (now,))
    base_url = db.get_setting("base_url").rstrip("/")
    return {"pending": [{
        "request_id": r["id"], "tool": r["tool"], "amount": r["amount"],
        "recipient": r["recipient"], "reason": r["reason"],
        "expires_in_sec": int(r["expires_at"] - now),
        "url": f"{base_url}/hitl/{r['id']}",
    } for r in rows]}


@app.get("/api/v1/health")
def health() -> dict:
    return {"ok": True, "rules": len(db.rows("SELECT id FROM rules")),
            "tools": len(catalog.TOOLS)}


@app.get("/api/v1/meta")
def meta() -> dict:
    """Справочники для вебморды: поля, операции, туллы, категории, списки."""
    return {
        "fields": catalog.FIELDS,
        "ops": catalog.OPS,
        "tools": catalog.TOOLS,
        "categories": catalog.CATEGORIES,
        "kind_titles": catalog.KIND_TITLES,
        "lists": [{"id": r["id"], "name": r["name"], "kind": r["kind"]}
                  for r in db.rows("SELECT id, name, kind FROM lists ORDER BY name")],
    }


# ── решение человека ─────────────────────────────────────────────────────────

def _decide(req_id: str, state: str, note: str, who: str) -> dict:
    row = db.one("SELECT * FROM hitl WHERE request_id=?", (req_id,))
    if row is None:
        raise HTTPException(404, "нет такого подтверждения")
    if row["state"] != "pending":
        return {"ok": False, "state": row["state"], "error": "решение уже принято"}
    now = time.time()
    if row["expires_at"] < now:
        db.run("UPDATE hitl SET state='expired' WHERE request_id=?", (req_id,))
        db.run("UPDATE requests SET status='expired' WHERE id=?", (req_id,))
        return {"ok": False, "state": "expired", "error": "срок подтверждения истёк"}
    db.run("UPDATE hitl SET state=?, decided_at=?, decided_by=?, note=? WHERE request_id=?",
           (state, now, who, note, req_id))
    if state == "approved":
        # В режиме wait исходный вызов ещё висит и ждёт — он же и выполнится,
        # поэтому запись становится allowed прямо здесь. В режиме async агент
        # придёт новым вызовом, и подтверждение спишется по отпечатку.
        if row["mode"] == "wait":
            db.run("UPDATE requests SET status='allowed', decision='allow' WHERE id=?", (req_id,))
            db.run("UPDATE hitl SET consumed_at=? WHERE request_id=?", (now, req_id))
    else:
        db.run("UPDATE requests SET status='denied', decision='deny' WHERE id=?", (req_id,))
    return {"ok": True, "state": state}


@app.post("/api/v1/hitl/{req_id}/approve")
def hitl_approve(req_id: str, payload: dict = Body(default={})) -> dict:
    return _decide(req_id, "approved", str(payload.get("note", "")), "web")


@app.post("/api/v1/hitl/{req_id}/deny")
def hitl_deny(req_id: str, payload: dict = Body(default={})) -> dict:
    return _decide(req_id, "denied", str(payload.get("note", "")), "web")


# ── CRUD политики ────────────────────────────────────────────────────────────

def _rule_row(row) -> dict:
    out = {"id": row["id"], "name": row["name"], "enabled": bool(row["enabled"]),
           "priority": row["priority"], "action": row["action"],
           "match": db.jload(row["match_json"], {}), "hitl_mode": row["hitl_mode"],
           "skip_limits": bool(row["skip_limits"]), "reason": row["reason"],
           "quota_window": row["quota_window"] or "",
           "quota_max_count": row["quota_max_count"],
           "quota_max_amount": row["quota_max_amount"],
           "quota_on_exceed": row["quota_on_exceed"] or "hitl"}
    if out["quota_window"]:
        used_count, used_amount = policy.rule_usage(row["id"], out["quota_window"])
        out["quota_used"] = {"count": used_count, "amount": used_amount}
    return out


@app.get("/api/v1/rules")
def rules_list() -> dict:
    return {"rules": [_rule_row(r) for r in
                      db.rows("SELECT * FROM rules ORDER BY priority, id")]}


@app.post("/api/v1/rules")
def rule_save(payload: dict = Body(...)) -> dict:
    now = time.time()
    match_json = json.dumps(payload.get("match") or {}, ensure_ascii=False)
    action = payload.get("action", "hitl")
    if action not in policy.SEVERITY:
        raise HTTPException(400, "action должен быть allow, deny или hitl")
    def _num(key, cast):
        value = payload.get(key)
        return cast(value) if value not in (None, "") else None

    quota_window = payload.get("quota_window") or ""
    if quota_window and quota_window not in ("hour", "day", "week", "month"):
        raise HTTPException(400, "quota_window: hour, day, week или month")
    quota = (quota_window, _num("quota_max_count", int), _num("quota_max_amount", float),
             payload.get("quota_on_exceed") or "hitl")

    if payload.get("id"):
        db.run("UPDATE rules SET name=?, enabled=?, priority=?, action=?, match_json=?, "
               "hitl_mode=?, skip_limits=?, reason=?, updated_at=?, quota_window=?, "
               "quota_max_count=?, quota_max_amount=?, quota_on_exceed=? WHERE id=?",
               (payload.get("name", ""), int(bool(payload.get("enabled", True))),
                int(payload.get("priority", 100)), action, match_json,
                payload.get("hitl_mode", ""), int(bool(payload.get("skip_limits"))),
                payload.get("reason", ""), now, *quota, int(payload["id"])))
        return {"ok": True, "id": int(payload["id"])}
    cur = db.run("INSERT INTO rules(name, enabled, priority, action, match_json, hitl_mode, "
                 "skip_limits, reason, created_at, updated_at, quota_window, "
                 "quota_max_count, quota_max_amount, quota_on_exceed) "
                 "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 (payload.get("name", "Без названия"),
                  int(bool(payload.get("enabled", True))),
                  int(payload.get("priority", 100)), action, match_json,
                  payload.get("hitl_mode", ""), int(bool(payload.get("skip_limits"))),
                  payload.get("reason", ""), now, now, *quota))
    return {"ok": True, "id": cur.lastrowid}


@app.delete("/api/v1/rules/{rule_id}")
def rule_delete(rule_id: int) -> dict:
    db.run("DELETE FROM rules WHERE id=?", (rule_id,))
    return {"ok": True}


@app.get("/api/v1/lists")
def lists_list() -> dict:
    return {"lists": [{"id": r["id"], "name": r["name"], "kind": r["kind"],
                       "note": r["note"], "entries": db.jload(r["entries_json"], [])}
                      for r in db.rows("SELECT * FROM lists ORDER BY id")]}


@app.post("/api/v1/lists")
def list_save(payload: dict = Body(...)) -> dict:
    entries = json.dumps(payload.get("entries") or [], ensure_ascii=False)
    if payload.get("id"):
        db.run("UPDATE lists SET name=?, kind=?, entries_json=?, note=? WHERE id=?",
               (payload.get("name", ""), payload.get("kind", "recipients"), entries,
                payload.get("note", ""), int(payload["id"])))
        return {"ok": True, "id": int(payload["id"])}
    cur = db.run("INSERT INTO lists(name, kind, entries_json, note, created_at) "
                 "VALUES (?,?,?,?,?)",
                 (payload.get("name", "Новый список"), payload.get("kind", "recipients"),
                  entries, payload.get("note", ""), time.time()))
    return {"ok": True, "id": cur.lastrowid}


@app.delete("/api/v1/lists/{list_id}")
def list_delete(list_id: int) -> dict:
    db.run("DELETE FROM lists WHERE id=?", (list_id,))
    return {"ok": True}


@app.get("/api/v1/limits")
def limits_list() -> dict:
    return {"limits": [{"id": r["id"], "name": r["name"], "enabled": bool(r["enabled"]),
                        "match": db.jload(r["match_json"], {}), "window": r["window"],
                        "max_amount": r["max_amount"], "max_count": r["max_count"],
                        "on_exceed": r["on_exceed"]}
                       for r in db.rows("SELECT * FROM limits ORDER BY id")]}


@app.post("/api/v1/limits")
def limit_save(payload: dict = Body(...)) -> dict:
    match_json = json.dumps(payload.get("match") or {}, ensure_ascii=False)
    amount = payload.get("max_amount")
    count = payload.get("max_count")
    amount = float(amount) if amount not in (None, "") else None
    count = int(count) if count not in (None, "") else None
    if payload.get("id"):
        db.run("UPDATE limits SET name=?, enabled=?, match_json=?, window=?, max_amount=?, "
               "max_count=?, on_exceed=? WHERE id=?",
               (payload.get("name", ""), int(bool(payload.get("enabled", True))), match_json,
                payload.get("window", "day"), amount, count,
                payload.get("on_exceed", "deny"), int(payload["id"])))
        return {"ok": True, "id": int(payload["id"])}
    cur = db.run("INSERT INTO limits(name, enabled, match_json, window, max_amount, "
                 "max_count, on_exceed, created_at) VALUES (?,?,?,?,?,?,?,?)",
                 (payload.get("name", "Новый лимит"),
                  int(bool(payload.get("enabled", True))), match_json,
                  payload.get("window", "day"), amount, count,
                  payload.get("on_exceed", "deny"), time.time()))
    return {"ok": True, "id": cur.lastrowid}


@app.delete("/api/v1/limits/{limit_id}")
def limit_delete(limit_id: int) -> dict:
    db.run("DELETE FROM limits WHERE id=?", (limit_id,))
    return {"ok": True}


@app.post("/api/v1/tools/{tool}/mode")
def tool_mode_set(tool: str, payload: dict = Body(...)) -> dict:
    mode = payload.get("mode", "on")
    if mode not in ("on", "blocked", "hidden"):
        raise HTTPException(400, "mode должен быть on, blocked или hidden")
    if mode == "on":
        db.run("DELETE FROM tool_modes WHERE tool=?", (tool,))
    else:
        db.run("INSERT INTO tool_modes(tool, mode) VALUES (?,?) "
               "ON CONFLICT(tool) DO UPDATE SET mode=excluded.mode", (tool, mode))
    return {"ok": True, "tool": tool, "mode": mode}


@app.get("/api/v1/settings")
def settings_get() -> dict:
    return db.settings()


@app.post("/api/v1/settings")
def settings_set(payload: dict = Body(...)) -> dict:
    for key, value in payload.items():
        if key in db.DEFAULT_SETTINGS:
            db.set_setting(key, value)
    return {"ok": True, "settings": db.settings()}


@app.post("/api/v1/simulate")
def simulate(payload: AuthorizeIn) -> dict:
    """Прогнать вызов через правила, ничего не записывая.

    Правило, которое нельзя проверить, не двигая настоящие деньги, никто не будет
    писать смелее чем «запретить всё»."""
    facets = facets_mod.extract(payload.tool, payload.args, payload.agent)
    decision = policy.evaluate(facets)
    return {"decision": decision.action, "reason": decision.reason,
            "rule": decision.rule_name, "facets": facets}


# ── вебморда ─────────────────────────────────────────────────────────────────

def _pretty(value) -> str:
    """JSON для показа человеку. Через шаблонный фильтр `tojson` кириллица
    превратилась бы в \\uXXXX, а весь смысл этих блоков — чтобы их читали."""
    return json.dumps(value, ensure_ascii=False, indent=2, default=str)


def _page(request: Request, name: str, **ctx) -> HTMLResponse:
    ctx.setdefault("catalog", catalog)
    ctx.setdefault("settings", db.settings())
    ctx.setdefault("nav", name)
    return templates.TemplateResponse(request, name + ".html", ctx)


@app.get("/", response_class=HTMLResponse)
def ui_index(request: Request):
    now = time.time()
    since = policy.window_start("day", now)
    stats = {
        "allowed": db.one("SELECT COUNT(*) c FROM requests WHERE ts>=? AND decision='allow'",
                          (since,))["c"],
        "denied": db.one("SELECT COUNT(*) c FROM requests WHERE ts>=? AND decision='deny'",
                         (since,))["c"],
        "hitl": db.one("SELECT COUNT(*) c FROM requests WHERE ts>=? AND decision='hitl'",
                       (since,))["c"],
        "spent": db.one(
            "SELECT COALESCE(SUM(amount),0) s FROM requests WHERE ts>=? AND kind='money' "
            "AND status IN ('allowed','executed','unknown')", (since,))["s"],
    }
    return _page(request, "index", stats=stats)


@app.get("/requests", response_class=HTMLResponse)
def ui_requests(request: Request, decision: str = Query(""), tool: str = Query("")):
    return _page(request, "requests", flt={"decision": decision, "tool": tool})


@app.get("/requests/{req_id}", response_class=HTMLResponse)
def ui_request(request: Request, req_id: str):
    row = db.one("SELECT * FROM requests WHERE id=?", (req_id,))
    if row is None:
        raise HTTPException(404, "нет такого запроса")
    hitl = db.one("SELECT * FROM hitl WHERE request_id=?", (req_id,))
    return _page(request, "request_detail", row=dict(row),
                 args_pretty=_pretty(db.jload(row["args_json"], {})),
                 facets_pretty=_pretty(db.jload(row["facets_json"], {})),
                 hitl=dict(hitl) if hitl else None)


@app.get("/hitl", response_class=HTMLResponse)
def ui_hitl(request: Request):
    return _page(request, "hitl")


@app.get("/hitl/{req_id}", response_class=HTMLResponse)
def ui_hitl_one(request: Request, req_id: str):
    row = db.one("SELECT * FROM requests WHERE id=?", (req_id,))
    if row is None:
        raise HTTPException(404, "нет такого запроса")
    hitl = db.one("SELECT * FROM hitl WHERE request_id=?", (req_id,))
    facets = db.jload(row["facets_json"], {})
    return _page(request, "hitl_one", row=dict(row), hitl=dict(hitl) if hitl else None,
                 facets=facets, args_pretty=_pretty(db.jload(row["args_json"], {})),
                 subject=_subject(facets))


@app.get("/rules", response_class=HTMLResponse)
def ui_rules(request: Request):
    return _page(request, "rules")


@app.get("/lists", response_class=HTMLResponse)
def ui_lists(request: Request):
    return _page(request, "lists")


@app.get("/limits", response_class=HTMLResponse)
def ui_limits(request: Request):
    return _page(request, "limits")


@app.get("/visibility", response_class=HTMLResponse)
def ui_visibility(request: Request):
    modes = {r["tool"]: r["mode"] for r in db.rows("SELECT tool, mode FROM tool_modes")}
    groups: dict[str, list] = {}
    for tool, (title, kind, cat) in catalog.TOOLS.items():
        groups.setdefault(cat, []).append(
            {"tool": tool, "title": title, "kind": kind, "mode": modes.get(tool, "on")})
    return _page(request, "visibility", groups=groups)


@app.get("/auth", response_class=HTMLResponse)
def ui_auth(request: Request):
    """Форма входа. Сам вход происходит НЕ здесь: страница ходит в демон на хосте
    напрямую, чтобы пароль не проходил через этот процесс. См. templates/auth.html."""
    return _page(request, "auth")


@app.get("/settings", response_class=HTMLResponse)
def ui_settings(request: Request):
    return _page(request, "settings")


@app.get("/api/v1/feed")
def feed(limit: int = 100, decision: str = "", tool: str = "") -> dict:
    sql = "SELECT * FROM requests WHERE 1=1"
    params: list = []
    if decision:
        sql += " AND decision=?"
        params.append(decision)
    if tool:
        sql += " AND tool LIKE ?"
        params.append(f"%{tool}%")
    sql += " ORDER BY ts DESC LIMIT ?"
    params.append(min(int(limit), 500))
    out = []
    for r in db.rows(sql, tuple(params)):
        out.append({
            "id": r["id"], "ts": r["ts"],
            "time": time.strftime("%d.%m %H:%M:%S", time.localtime(r["ts"])),
            "tool": r["tool"], "title": catalog.title_of(r["tool"]), "kind": r["kind"],
            "category": r["category"], "amount": r["amount"],
            "recipient": r["recipient"], "decision": r["decision"], "status": r["status"],
            "reason": r["reason"], "rule": r["rule_name"], "head": r["output_head"],
        })
    return {"feed": out}


def main() -> None:  # pragma: no cover
    import uvicorn
    import os
    uvicorn.run(app, host=os.environ.get("TBANK_FW_HOST", "0.0.0.0"),
                port=int(os.environ.get("TBANK_FW_PORT", "8080")))


if __name__ == "__main__":  # pragma: no cover
    main()
