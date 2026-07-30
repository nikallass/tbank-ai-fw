"""Движок правил: сопоставление, списки, лимиты, приоритеты.

Без сервера и без сети — только политика. Это те проверки, которые должны падать
громко: ошибка здесь означает, что деньги ушли туда, куда владелец не разрешал.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_TMP = tempfile.mkdtemp(prefix="fwtest-")
os.environ["TBANK_FW_DB"] = os.path.join(_TMP, "t.db")

from app import db, facets, policy, seed  # noqa: E402

db.DB_PATH = os.environ["TBANK_FW_DB"]
db.init()
seed.seed_if_empty()

FAILS: list[str] = []


def check(label: str, got, want) -> None:
    if got != want:
        FAILS.append(f"{label}: получено {got!r}, ожидалось {want!r}")


def decide(tool: str, args: dict) -> policy.Decision:
    return policy.evaluate(facets.extract(tool, args, "test"))


# ── нормализация получателя ──────────────────────────────────────────────────
for raw in ("+7 999 123-45-67", "89991234567", "79991234567", "9991234567"):
    check(f"нормализация {raw}", facets.norm_phone(raw), "+79991234567")
check("не телефон не трогаем", facets.norm_phone("40817810000000000001"),
      "40817810000000000001")

# ── факты вытаскиваются из разных имён аргументов ────────────────────────────
f = facets.extract("transfer", {"amount": 100, "to_account": "89991234567",
                                "description": "обед", "from_account": "ACC1"})
check("сумма перевода", f["amount"], 100.0)
check("получатель перевода", f["recipient"], "+79991234567")
check("счёт списания", f["from_account"], "ACC1")
check("текст перевода", f["text"], "обед")

f = facets.extract("grocery_checkout", {"expected_sum": 2500, "app_id": "shop-1"})
check("сумма чекаута из expected_sum", f["amount"], 2500.0)
check("магазин как организация", f["org"], "shop-1")

f = facets.extract("ticket_pay", {"amount": 900, "order_id": "ORD-7"})
check("сумма билета", f["amount"], 900.0)

# ── kind берётся из НАШЕЙ таблицы, а не из того, что прислали ────────────────
check("kind перевода", facets.extract("transfer", {})["kind"], "money")
check("неизвестный тул считается денежным",
      facets.extract("what_is_this", {})["kind"], "money")

# ── базовые решения сид-политики ─────────────────────────────────────────────
check("чтение разрешено", decide("list_accounts", {}).action, policy.ALLOW)
check("корзина разрешена", decide("grocery_add_to_cart", {"items": "[]"}).action,
      policy.ALLOW)
check("деньги идут на подтверждение",
      decide("transfer", {"amount": 500, "to_account": "+79990000000"}).action,
      policy.HITL)
check("сообщение человеку — на подтверждение",
      decide("messenger_send", {"conversation_id": "c1", "text": "привет"}).action,
      policy.HITL)

# ── стоп-слова: регулярка и подстрока ────────────────────────────────────────
check("стоп-слово регуляркой",
      decide("transfer", {"amount": 10, "to_account": "+79990000000",
                          "description": "на крипту"}).action, policy.DENY)
check("стоп-слово в поиске тоже ловится",
      decide("search_app", {"query": "казино рядом"}).action, policy.DENY)
check("обычный текст проходит",
      decide("search_app", {"query": "ближайший банкомат"}).action, policy.ALLOW)

# ── лимиты ───────────────────────────────────────────────────────────────────
d = decide("transfer", {"amount": 99999, "to_account": "+79990000000"})
check("потолок одной операции запрещает", d.action, policy.DENY)
assert "15 000" in d.reason or "15000" in d.reason, d.reason

# ── чекаут без подтверждённой суммы ──────────────────────────────────────────
check("чекаут без expected_sum запрещён",
      decide("grocery_checkout", {"app_id": "s", "point_id": "p"}).action, policy.DENY)
check("чекаут с суммой идёт на подтверждение",
      decide("grocery_checkout", {"app_id": "s", "point_id": "p",
                                  "expected_sum": 1200}).action, policy.HITL)

# ── реквизиты карты с раскрытием ─────────────────────────────────────────────
check("маскированные реквизиты — чтение",
      decide("card_requisites", {"ucid": "u1"}).action, policy.ALLOW)
check("полные реквизиты — подтверждение",
      decide("card_requisites", {"ucid": "u1", "reveal": True}).action, policy.HITL)

# ── белый список: правило выключено, включаем и проверяем обе стороны ────────
lst = db.one("SELECT id FROM lists WHERE name='Доверенные получатели'")
db.run("UPDATE lists SET entries_json=? WHERE id=?",
       (json.dumps([{"match": "exact", "value": "+79991234567"}]), lst["id"]))
db.run("UPDATE rules SET enabled=1 WHERE name LIKE 'Только доверенные%'")

check("чужой получатель запрещён белым списком",
      decide("transfer", {"amount": 100, "to_account": "+79997776655"}).action,
      policy.DENY)
check("доверенный до 1000 ₽ проходит без вопросов",
      decide("transfer", {"amount": 100, "to_account": "8 999 123-45-67"}).action,
      policy.ALLOW)
check("доверенный, но крупная сумма — подтверждение",
      decide("transfer", {"amount": 5000, "to_account": "+79991234567"}).action,
      policy.HITL)
db.run("UPDATE rules SET enabled=0 WHERE name LIKE 'Только доверенные%'")

# ── чёрный список сильнее белого: он выше по приоритету ──────────────────────
black = db.one("SELECT id FROM lists WHERE name='Запрещённые получатели'")
db.run("UPDATE lists SET entries_json=? WHERE id=?",
       (json.dumps([{"match": "exact", "value": "+79991234567"}]), black["id"]))
check("чёрный список перебивает доверие",
      decide("transfer", {"amount": 100, "to_account": "+79991234567"}).action,
      policy.DENY)
db.run("UPDATE lists SET entries_json='[]' WHERE id=?", (black["id"],))

# ── лимит по сумме за сутки учитывает уже проведённые операции ───────────────
now = time.time()
for i in range(3):
    db.run(
        "INSERT INTO requests(id, ts, tool, kind, category, args_json, facets_json, "
        "amount, decision, status) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (f"seedreq{i}", now, "transfer", "money", "transfer", "{}",
         json.dumps({"tool": "transfer", "kind": "money", "category": "transfer"}),
         9000.0, "allow", "executed"))
d = decide("transfer", {"amount": 5000, "to_account": "+79990000000"})
check("суточный потолок 30k пробит 27k+5k", d.action, policy.DENY)

# Отклонённые операции потолок не расходуют.
db.run("UPDATE requests SET status='denied' WHERE id LIKE 'seedreq%'")
check("отклонённые не расходуют лимит",
      decide("transfer", {"amount": 5000, "to_account": "+79990000000"}).action,
      policy.HITL)

# ── режим тула перекрывает любые правила ─────────────────────────────────────
db.run("INSERT OR REPLACE INTO tool_modes(tool, mode) VALUES ('list_accounts','blocked')")
check("выключенный тул запрещён даже при allow-правиле",
      decide("list_accounts", {}).action, policy.DENY)
db.run("DELETE FROM tool_modes WHERE tool='list_accounts'")

# ── сравнение с отсутствующей суммой не срабатывает молча ────────────────────
check("amount gt при пустой сумме не совпадает",
      policy.eval_condition({"field": "amount", "op": "gt", "value": 100},
                            {"amount": None}), False)

# ── сломанная регулярка не роняет разбор ─────────────────────────────────────
check("битая регулярка = не совпало",
      policy.eval_condition({"field": "text", "op": "regex", "value": "([unclosed"},
                            {"text": "что угодно"}), False)

# ── секреты не попадают в журнал ─────────────────────────────────────────────
scrubbed = facets.scrub_args({"password": "hunter2", "otp": "1234", "amount": 5})
check("пароль не сохраняется", "hunter2" in json.dumps(scrubbed, ensure_ascii=False), False)
check("otp не сохраняется", "1234" in json.dumps(scrubbed, ensure_ascii=False), False)
check("обычный аргумент сохраняется", scrubbed["amount"], 5)

# ── отпечаток вызова ─────────────────────────────────────────────────────────
sig_a = facets.signature("transfer", {"amount": 100, "to_account": "+79991234567"})
sig_b = facets.signature("transfer", {"to_account": "+79991234567", "amount": 100})
sig_c = facets.signature("transfer", {"amount": 101, "to_account": "+79991234567"})
check("порядок аргументов не влияет на отпечаток", sig_a, sig_b)
check("другая сумма — другой отпечаток", sig_a == sig_c, False)

# ── квота правила: N раз в сутки без подтверждения, дальше — спросить ───────
db.run("DELETE FROM requests")
db.run("UPDATE rules SET enabled=0 WHERE priority IN (50, 55)")
qid = db.run(
    "INSERT INTO rules(name, enabled, priority, action, match_json, hitl_mode, "
    "skip_limits, reason, created_at, updated_at, quota_window, quota_max_count, "
    "quota_max_amount, quota_on_exceed) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    ("Мелочь по норме", 1, 55, "allow",
     json.dumps({"kinds": ["money"],
                 "conditions": [{"field": "amount", "op": "lte", "value": 3000}]}),
     "", 0, "мелкая трата в пределах нормы", time.time(), time.time(),
     "day", 3, 6000.0, "hitl")).lastrowid


def spend(amount: float) -> policy.Decision:
    """Провести операцию так, как это сделал бы authorize: решить и записать."""
    f = facets.extract("transfer", {"amount": amount, "to_account": "+79990000000"}, "test")
    d = policy.evaluate(f)
    db.run("INSERT INTO requests(id, ts, tool, kind, category, args_json, facets_json, "
           "amount, decision, status, rule_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
           (f"q{time.time_ns()}", time.time(), "transfer", "money", "transfer", "{}",
            json.dumps(f, default=str), amount, d.action,
            "allowed" if d.action == policy.ALLOW else "pending",
            d.rule_id if d.action == policy.ALLOW else None))
    return d


check("1-я мелкая трата проходит молча", spend(1000).action, policy.ALLOW)
check("2-я тоже", spend(1000).action, policy.ALLOW)
check("3-я тоже", spend(1000).action, policy.ALLOW)
d = spend(1000)
check("4-я уходит на подтверждение", d.action, policy.HITL)
assert "3 раз" in d.reason and "4-й" in d.reason, d.reason

# Крупная трата под квоту не подпадает и идёт по общему правилу про деньги.
check("трата вне нормы разбирается общим правилом",
      policy.evaluate(facets.extract("transfer", {"amount": 5000,
                                                  "to_account": "+79990000000"})).action,
      policy.HITL)

# Квота по СУММЕ, независимо от числа операций.
db.run("DELETE FROM requests")
db.run("UPDATE rules SET quota_max_count=NULL WHERE id=?", (qid,))
check("2500 ₽ в пределах суммарной нормы", spend(2500).action, policy.ALLOW)
check("ещё 2500 ₽ тоже", spend(2500).action, policy.ALLOW)
d = spend(2500)
check("третья пробивает норму 6000 ₽ по сумме", d.action, policy.HITL)
assert "6000.00 ₽" in d.reason, d.reason

# Подтверждённые человеком операции норму НЕ расходуют: у них нет rule_id.
db.run("DELETE FROM requests")
db.run("UPDATE rules SET quota_max_count=3, quota_max_amount=NULL WHERE id=?", (qid,))
for i in range(5):
    db.run("INSERT INTO requests(id, ts, tool, kind, category, args_json, facets_json, "
           "amount, decision, status, rule_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
           (f"appr{i}", time.time(), "transfer", "money", "transfer", "{}", "{}",
            1000.0, "allow", "allowed", None))
check("подтверждённые вручную не съедают норму", spend(1000).action, policy.ALLOW)

# Отключённая квота возвращает правилу обычное поведение.
db.run("DELETE FROM requests")
db.run("UPDATE rules SET quota_window='' WHERE id=?", (qid,))
for _ in range(6):
    spend(1000)
check("без квоты правило разрешает без ограничений", spend(1000).action, policy.ALLOW)
db.run("DELETE FROM rules WHERE id=?", (qid,))
db.run("DELETE FROM requests")

if FAILS:
    print("ПРОВАЛЫ:")
    for f in FAILS:
        print("  -", f)
    sys.exit(1)
print("test_policy: ок")
