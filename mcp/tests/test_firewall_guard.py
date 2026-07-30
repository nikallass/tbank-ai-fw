"""Врезка фаервола: что происходит вокруг вызова тула.

Против ЗАГЛУШКИ фаервола, а не против настоящего сервиса: проверяется контракт
guard.py — что он спрашивает, что делает с каждым ответом и, главное, что при
запрете сам тул НЕ ВЫЗЫВАЕТСЯ. Настоящий сервис проверяется своими тестами
(`firewall/tests/`), и оба конца сходятся на одном JSON.

    .venv/bin/python tests/test_firewall_guard.py
"""
from __future__ import annotations

import importlib
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

failures: list[str] = []


def check(cond, msg: str) -> None:
    if not cond:
        failures.append(msg)


# ── заглушка фаервола ────────────────────────────────────────────────────────

STATE = {
    "decision": {"decision": "allow", "request_id": "req_test"},
    "request_state": {"hitl_state": "pending"},
    "hidden": [],
    "seen": [],            # что guard прислал на authorize
    "results": [],         # что guard прислал на result
}


class Stub(BaseHTTPRequestHandler):
    def log_message(self, *a):  # тишина в выводе теста
        pass

    def _send(self, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/v1/visibility":
            return self._send({"hidden": STATE["hidden"], "blocked": [], "modes": {}})
        if self.path.startswith("/api/v1/requests/"):
            return self._send(STATE["request_state"])
        return self._send({})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        payload = json.loads(raw or b"{}")
        if self.path == "/api/v1/authorize":
            STATE["seen"].append(payload)
            return self._send(STATE["decision"])
        if self.path.endswith("/result"):
            STATE["results"].append(payload)
            # Заглушка маскирует ровно одно — этого хватает, чтобы доказать, что
            # guard возвращает агенту ОТВЕТ ФАЕРВОЛА, а не собственный.
            return self._send({"output": (payload.get("output") or "").replace(
                "5536913812345678", "••••••••••••5678")})
        return self._send({})


server = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
threading.Thread(target=server.serve_forever, daemon=True).start()
URL = f"http://127.0.0.1:{server.server_address[1]}"

os.environ["TBANK_FIREWALL_URL"] = URL
os.environ["TBANK_FIREWALL"] = "1"
os.environ["TBANK_FIREWALL_FAILMODE"] = "closed"
os.environ["TBANK_FIREWALL_TIMEOUT"] = "5"

from src import guard  # noqa: E402

guard = importlib.reload(guard)

CALLS: list[tuple] = []


def fake_transfer(amount: float, to_account: str, description: str = "",
                  force: bool = False) -> str:
    CALLS.append((amount, to_account, description, force))
    return f"Отправлено {amount} → {to_account}. Карта 5536913812345678"


wrapped = guard.wrap(fake_transfer, "transfer", "money")


def run(**kw):
    CALLS.clear()
    STATE["seen"].clear()
    STATE["results"].clear()
    return wrapped(**kw)


# ── разрешено: тул выполняется, ответ проходит через маски фаервола ──────────
STATE["decision"] = {"decision": "allow", "request_id": "req_ok"}
out = run(amount=100, to_account="+79991234567")
check(len(CALLS) == 1, "разрешённый вызов не дошёл до тула")
check("••••••••••••5678" in out,
      f"guard вернул не тот текст, что отдал фаервол: {out!r}")
check("5536913812345678" not in out, "номер карты дошёл до агента")
check(STATE["results"] and STATE["results"][0]["status"] == "ok",
      f"исход не записан как ok: {STATE['results']}")

# ── аргументы уходят целиком, включая умолчания ──────────────────────────────
sent = STATE["seen"][0]
check(sent["tool"] == "transfer", f"не то имя тула: {sent['tool']}")
check(sent["kind"] == "money", f"не тот kind: {sent['kind']}")
check(sent["args"]["amount"] == 100, f"сумма не передана: {sent['args']}")
check(sent["args"].get("force") is False,
      f"умолчания не переданы, правило про них не сработает: {sent['args']}")

# ── запрещено: тул НЕ вызывается, агент получает текст фаервола ──────────────
STATE["decision"] = {"decision": "deny", "request_id": "req_no",
                     "message": "🚫 ЗАБЛОКИРОВАНО ФАЕРВОЛОМ: тест"}
out = run(amount=100, to_account="+79991234567")
check(not CALLS, "ЗАПРЕЩЁННЫЙ ВЫЗОВ ВСЁ РАВНО ДОШЁЛ ДО БАНКА")
check(out.startswith("🚫"), f"агенту не отдали причину отказа: {out!r}")
check(not STATE["results"], "по заблокированному вызову записан результат")

# ── подтверждение, режим async: вызов не выполняется, агент получает ссылку ──
STATE["decision"] = {"decision": "hitl", "request_id": "req_wait",
                     "hitl": {"mode": "async", "url": URL + "/hitl/req_wait",
                              "ttl_sec": 900, "wait_sec": 5},
                     "message": "⏳ НУЖНО ПОДТВЕРЖДЕНИЕ: открой ссылку"}
out = run(amount=5000, to_account="+79991234567")
check(not CALLS, "вызов выполнился, не дождавшись подтверждения")
check("⏳" in out, f"агенту не отдали инструкцию: {out!r}")

# ── подтверждение, режим wait: одобрили — вызов идёт ─────────────────────────
STATE["decision"] = {"decision": "hitl", "request_id": "req_w2",
                     "hitl": {"mode": "wait", "wait_sec": 8},
                     "message": "⏳ ждём"}
STATE["request_state"] = {"hitl_state": "approved"}
out = run(amount=300, to_account="+79991234567")
check(len(CALLS) == 1, "подтверждённый вызов в режиме wait не выполнился")

# ── подтверждение, режим wait: отклонили — вызова нет ────────────────────────
STATE["request_state"] = {"hitl_state": "denied", "note": "не надо"}
out = run(amount=300, to_account="+79991234567")
check(not CALLS, "ОТКЛОНЁННЫЙ ВЫЗОВ ВЫПОЛНИЛСЯ")
check("отклонил" in out, f"агенту не сказали, что отклонили: {out!r}")

# ── длинный опрос: операция доводится до конца в ОДНОМ ходе агента ──────────
# Без него цепочка рвётся: агент отдал ссылку, человек нажал кнопку, а разбудить
# чат некому — у MCP нет обратного канала.
STATE["request_state"] = {"hitl_state": "pending"}
threading.Timer(1.5, lambda: STATE.__setitem__(
    "request_state", {"hitl_state": "approved"})).start()
t0 = time.time()
res = guard.await_decision("req_poll", wait_sec=20)
waited = time.time() - t0
check(res.get("hitl_state") == "approved",
      f"длинный опрос не дождался решения: {res}")
check(waited < 10, f"решение подхвачено за {waited:.1f}с — слишком поздно")
check(waited >= 1.0, f"вернулся раньше решения ({waited:.1f}с)")

# Время вышло, а решения нет — возвращаем pending, а не выдумываем отказ.
STATE["request_state"] = {"hitl_state": "pending"}
t0 = time.time()
res = guard.await_decision("req_poll", wait_sec=3)
check(res.get("hitl_state") == "pending", f"по таймауту вернулось не pending: {res}")
check(2.0 <= time.time() - t0 <= 8.0, "таймаут ожидания не соблюдён")

# wait_sec=0 — просто посмотреть, не задерживаясь.
t0 = time.time()
guard.await_decision("req_poll", wait_sec=0)
check(time.time() - t0 < 1.0, "wait_sec=0 всё равно ждал")

# ── исход «деньги могли уйти» отличается от «деньги на месте» ────────────────
STATE["decision"] = {"decision": "allow", "request_id": "req_out"}
check(guard._outcome("ИСХОД НЕИЗВЕСТЕН: таймаут") == "unknown",
      "неизвестный исход записан как успешный — лимит не удержит эти деньги")
check(guard._outcome("Перевод НЕ выполнен: ошибка") == "error",
      "неудача записана как проведённая операция — лимит съеден зря")
check(guard._outcome("Отправлено 100 ₽") == "ok", "успех записан неверно")

# ── исключение из тула не теряется, но фиксируется ───────────────────────────
def boom(x: int = 1) -> str:
    raise RuntimeError("банк лёг")


raised = False
try:
    STATE["results"].clear()
    guard.wrap(boom, "transfer", "money")(x=1)
except RuntimeError:
    raised = True
check(raised, "исключение тула проглочено — агент решит, что всё хорошо")
check(STATE["results"] and STATE["results"][-1]["status"] == "error",
      "падение тула не записано в журнал фаервола")

# ── фаервол недоступен: closed запрещает, open пропускает ────────────────────
os.environ["TBANK_FIREWALL_URL"] = "http://127.0.0.1:1"     # никто не слушает
for mode, expect_call, label in (("closed", False, "closed обязан запретить"),
                                 ("read-open", False, "read-open не про деньги"),
                                 ("open", True, "open обязан пропустить")):
    os.environ["TBANK_FIREWALL_FAILMODE"] = mode
    g2 = importlib.reload(guard)
    CALLS.clear()
    out = g2.wrap(fake_transfer, "transfer", "money")(amount=1, to_account="+79990000000")
    check(bool(CALLS) is expect_call, f"failmode={mode}: {label} (вызовов: {len(CALLS)})")
    if not expect_call:
        check("недоступен" in out, f"failmode={mode}: агенту не объяснили причину: {out!r}")

# read-open пропускает именно чтение
os.environ["TBANK_FIREWALL_FAILMODE"] = "read-open"
g3 = importlib.reload(guard)
CALLS.clear()
g3.wrap(fake_transfer, "list_accounts", "read")(amount=0, to_account="")
check(len(CALLS) == 1, "read-open не пропустил чтение при недоступном фаерволе")

# ── выключенный фаервол не трогает функцию вообще ───────────────────────────
os.environ["TBANK_FIREWALL"] = "0"
g4 = importlib.reload(guard)
check(g4.wrap(fake_transfer, "transfer", "money") is fake_transfer,
      "TBANK_FIREWALL=0 всё равно оборачивает тул")

server.shutdown()

if failures:
    print("ПРОВАЛЫ:")
    for f in failures:
        print("  -", f)
    sys.exit(1)
print("firewall guard: ок — запрет не доходит до банка, ответ идёт через маски")
