"""HTTP-контракт фаервола: авторизация вызова, подтверждение, результат, маски.

Проверяется ровно то, на что опирается MCP. Если этот файл позеленел, а MCP
всё равно ведёт себя странно — расхождение в guard.py, а не здесь.
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_TMP = tempfile.mkdtemp(prefix="fwapi-")
os.environ["TBANK_FW_DB"] = os.path.join(_TMP, "t.db")

from fastapi.testclient import TestClient  # noqa: E402

from app import db  # noqa: E402

db.DB_PATH = os.environ["TBANK_FW_DB"]

from app.main import app  # noqa: E402

FAILS: list[str] = []


def check(label: str, got, want) -> None:
    if got != want:
        FAILS.append(f"{label}: получено {got!r}, ожидалось {want!r}")


TRANSFER = {"tool": "transfer", "agent": "test",
            "args": {"amount": 500, "to_account": "+79991234567", "description": "обед"}}

with TestClient(app) as c:
    check("health", c.get("/api/v1/health").json()["ok"], True)

    # ── чтение проходит без вопросов ─────────────────────────────────────────
    r = c.post("/api/v1/authorize", json={"tool": "list_accounts", "args": {}}).json()
    check("чтение разрешено", r["decision"], "allow")
    check("на разрешении нет текста для агента", r["message"], "")

    # ── деньги уходят на подтверждение ───────────────────────────────────────
    r = c.post("/api/v1/authorize", json=TRANSFER).json()
    check("перевод на подтверждении", r["decision"], "hitl")
    rid = r["request_id"]
    assert rid.startswith("req_"), rid
    assert rid in r["hitl"]["url"], r["hitl"]["url"]
    assert "500.00 ₽" in r["message"], r["message"]
    assert "+79991234567" in r["message"], r["message"]

    # ── повтор до решения НЕ плодит вторую карточку ──────────────────────────
    again = c.post("/api/v1/authorize", json=TRANSFER).json()
    check("повтор попадает в то же подтверждение", again["request_id"], rid)
    check("в очереди одна карточка", len(c.get("/api/v1/pending").json()["pending"]), 1)

    # ── человек подтверждает ─────────────────────────────────────────────────
    ok = c.post(f"/api/v1/hitl/{rid}/approve", json={"note": "да, за обед"}).json()
    check("подтверждение принято", ok["ok"], True)
    check("статус для агента", c.get(f"/api/v1/requests/{rid}").json()["hitl_state"],
          "approved")

    # ── тот же вызов теперь проходит, и ровно один раз ───────────────────────
    r = c.post("/api/v1/authorize", json=TRANSFER).json()
    check("подтверждённый вызов разрешён", r["decision"], "allow")
    assert "подтверждено владельцем" in r["reason"], r["reason"]
    r2 = c.post("/api/v1/authorize", json=TRANSFER).json()
    check("подтверждение одноразовое", r2["decision"], "hitl")

    # ── другая сумма подтверждением не покрывается ───────────────────────────
    other = dict(TRANSFER, args=dict(TRANSFER["args"], amount=9000))
    check("другая сумма спрашивает заново",
          c.post("/api/v1/authorize", json=other).json()["decision"], "hitl")

    # ── отклонение ───────────────────────────────────────────────────────────
    rid3 = c.post("/api/v1/authorize", json=dict(
        TRANSFER, args=dict(TRANSFER["args"], amount=777))).json()["request_id"]
    c.post(f"/api/v1/hitl/{rid3}/deny", json={"note": "не надо"})
    check("отклонённое остаётся отклонённым",
          c.get(f"/api/v1/requests/{rid3}").json()["status"], "denied")
    check("повторное решение не проходит",
          c.post(f"/api/v1/hitl/{rid3}/approve", json={}).json()["ok"], False)

    # ── явный запрет виден агенту с причиной ─────────────────────────────────
    r = c.post("/api/v1/authorize", json={
        "tool": "transfer", "args": {"amount": 10, "to_account": "+79990000000",
                                     "description": "перевод на крипту"}}).json()
    check("стоп-слово запрещает", r["decision"], "deny")
    assert "ЗАБЛОКИРОВАНО" in r["message"], r["message"]
    assert "Повторять этот вызов бессмысленно" in r["message"], r["message"]

    # ── результат вызова маскируется на обратном пути ────────────────────────
    rid4 = c.post("/api/v1/authorize", json={
        "tool": "card_requisites", "args": {"ucid": "u1"}}).json()["request_id"]
    out = c.post(f"/api/v1/requests/{rid4}/result", json={
        "status": "ok", "ms": 12,
        "output": "Карта 5536913812345678, CVV: 123, до 09/28"}).json()["output"]
    check("номер карты замаскирован", "5536913812345678" in out, False)
    check("хвост карты остался", out.count("5678"), 1)
    check("cvv замаскирован", "123," in out, False)

    # ── журнал показывает, что произошло ─────────────────────────────────────
    feed = c.get("/api/v1/feed?limit=50").json()["feed"]
    assert len(feed) >= 6, len(feed)
    check("в журнале есть отказ", any(x["decision"] == "deny" for x in feed), True)

    # ── симулятор ничего не пишет ────────────────────────────────────────────
    before = len(c.get("/api/v1/feed?limit=500").json()["feed"])
    sim = c.post("/api/v1/simulate", json=TRANSFER).json()
    check("симулятор возвращает решение", sim["decision"] in ("allow", "hitl", "deny"), True)
    after = len(c.get("/api/v1/feed?limit=500").json()["feed"])
    check("симулятор не пишет в журнал", after, before)

    # ── зона видимости ───────────────────────────────────────────────────────
    c.post("/api/v1/tools/messenger_send/mode", json={"mode": "hidden"})
    check("скрытый тул в списке скрытых",
          "messenger_send" in c.get("/api/v1/visibility").json()["hidden"], True)
    check("скрытый тул запрещён",
          c.post("/api/v1/authorize", json={
              "tool": "messenger_send", "args": {"conversation_id": "c", "text": "hi"}
          }).json()["decision"], "deny")
    c.post("/api/v1/tools/messenger_send/mode", json={"mode": "on"})

    # ── выдуманные реквизиты СБП не проходят ─────────────────────────────────
    # Ровно тот случай, который стоил живого платежа: банк ответил «слишком много
    # попыток», модель подставила правдоподобные цифры и пошла платить.
    INVENTED = {"tool": "transfer", "agent": "test", "args": {
        "amount": 100, "to_account": "+79770001122",
        "bank_member_id": "100000000004", "pointer_link_id": "52574125739"}}
    r = c.post("/api/v1/authorize", json=INVENTED).json()
    check("сочинённые реквизиты без резолва запрещены", r["decision"], "deny")
    assert "не возвращал" in r["reason"], r["reason"]

    # Резолв прошёл — фаервол запомнил, что именно назвал банк.
    rid_res = c.post("/api/v1/authorize", json={
        "tool": "transfer_sbp_resolve", "args": {"phone": "+79770001122"}}).json()["request_id"]
    c.post(f"/api/v1/requests/{rid_res}/result", json={"status": "ok", "output": (
        "+79770001122: найдено банков СБП — 2\n"
        "- И. ИВАНОВ | Т-Банк ★ДЕФОЛТ\n"
        '  providerFields: {"pointerType": "8276", "pointer": "+79770001122", '
        '"bankMemberId": "100000000111", "maskedFIO": "И. ИВАНОВ", '
        '"pointerLinkId": "999888777"}\n'
        "- И. ИВАНОВ | Сбер\n"
        '  providerFields: {"pointerType": "8276", "pointer": "+79770001122", '
        '"bankMemberId": "100000000222", "maskedFIO": "И. ИВАНОВ", '
        '"pointerLinkId": "111222333"}')})

    # Те же выдуманные цифры теперь отвергаются с указанием настоящих.
    r = c.post("/api/v1/authorize", json=INVENTED).json()
    check("после резолва сочинённые реквизиты всё равно запрещены", r["decision"], "deny")
    assert "100000000111" in r["reason"], r["reason"]

    # А настоящая пара из ответа банка проходит разбор дальше, к правилам.
    real = {"tool": "transfer", "agent": "test", "args": {
        "amount": 100, "to_account": "+79770001122",
        "bank_member_id": "100000000222", "pointer_link_id": "111222333"}}
    check("реквизиты из ответа банка проходят",
          c.post("/api/v1/authorize", json=real).json()["decision"], "hitl")

    # Без реквизитов вообще — тоже проходит: клиент резолвит получателя сам.
    check("пустые реквизиты не блокируются",
          c.post("/api/v1/authorize", json={"tool": "transfer", "args": {
              "amount": 100, "to_account": "+79770001122"}}).json()["decision"], "hitl")

    # Проверку можно выключить — но по умолчанию она включена.
    c.post("/api/v1/settings", json={"require_resolved_requisites": "0"})
    check("выключенная проверка пропускает",
          c.post("/api/v1/authorize", json=INVENTED).json()["decision"], "hitl")
    c.post("/api/v1/settings", json={"require_resolved_requisites": "1"})

    # ── квота: три мелких платежа молча, четвёртый спрашивает ────────────────
    made = c.post("/api/v1/rules", json={
        "name": "Мелочь по норме", "priority": 55, "action": "allow", "enabled": True,
        "reason": "мелкая трата в пределах суточной нормы",
        "match": {"kinds": ["money"],
                  "conditions": [{"field": "amount", "op": "lte", "value": 3000}]},
        "quota_window": "day", "quota_max_count": 3, "quota_on_exceed": "hitl",
    }).json()
    check("правило с квотой создано", made["ok"], True)

    def small(n):
        return c.post("/api/v1/authorize", json={
            "tool": "transfer", "agent": "test",
            "args": {"amount": 900, "to_account": "+79995550000", "description": f"кофе {n}"},
        }).json()

    for i in range(3):
        check(f"мелкий платёж {i + 1} проходит молча", small(i)["decision"], "allow")
    fourth = small(3)
    check("четвёртый уходит на подтверждение", fourth["decision"], "hitl")
    assert "3 раз" in fourth["reason"], fourth["reason"]

    quota_rule = next(r for r in c.get("/api/v1/rules").json()["rules"]
                      if r["id"] == made["id"])
    check("израсходованное показывается в правиле", quota_rule["quota_used"]["count"], 3)

    # Расход считается только по этому правилу — крупная трата его не трогает.
    c.post("/api/v1/authorize", json={"tool": "transfer", "args": {
        "amount": 12000, "to_account": "+79995550000"}})
    quota_rule = next(r for r in c.get("/api/v1/rules").json()["rules"]
                      if r["id"] == made["id"])
    check("чужая операция норму не расходует", quota_rule["quota_used"]["count"], 3)
    c.request("DELETE", f"/api/v1/rules/{made['id']}")

    # ── страницы отдаются ────────────────────────────────────────────────────
    for path in ("/", "/rules", "/lists", "/limits", "/visibility", "/settings",
                 "/auth", "/hitl", "/requests", f"/requests/{rid}", f"/hitl/{rid}"):
        check(f"страница {path}", c.get(path).status_code, 200)

if FAILS:
    print("ПРОВАЛЫ:")
    for f in FAILS:
        print("  -", f)
    sys.exit(1)
print("test_api: ок")
