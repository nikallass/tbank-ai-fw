"""Платёжный шлюз требует sessionid уровня CLIENT — иначе 403.

ЧТО СЛУЧИЛОСЬ. Переводы стабильно не проходили: то голый `403 Forbidden` от
шлюза, то `INTERNAL_ERROR — по техническим причинам сервис недоступен`. Чтения
при этом работали, и это сбивало с толку дольше всего: выглядело как блокировка
по антифроду или как неверное тело запроса. Сверка запроса с захватом ничего не
дала — тело совпадало ключ в ключ.

ПРИЧИНА. Эндпоинты платёжного шлюза проверяют SESSIONID, а не Bearer. Окно
CLIENT у sessionid ~11 минут против ~2 часов у токена (см.
`MobileSession.ensure_client_session`). Денежный путь поднимал только свежесть
токена (`ensure_fresh`) и уровень не трогал — а протухший sessionid читается как
ANONYMOUS, и шлюз отвечает общей ошибкой, неотличимой от аварии.

ДОКАЗАНО НА ЖИВОМ СЧЁТЕ. `payment_commission` (денег не двигает) с одним
`ensure_fresh` вернул `HTTP_403: Forbidden`; сразу после `ensure_client_session()`
тот же самый вызов посчитал комиссию.

    .venv/bin/python tests/test_payment_gate_level.py
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.setdefault("TBANK_FIREWALL", "0")
os.environ.setdefault("TBANK_TRACE", "0")

from src.client import MobileSession                             # noqa: E402

failures: list[str] = []


def check(cond, msg: str) -> None:
    if not cond:
        failures.append(msg)


class Spy(MobileSession):
    """Считает поднятия уровня и запоминает, что было поднято ДО запроса."""

    def __init__(self):
        self.raised = 0
        self.raised_before = {}
        self.seen = []
        self.mobile_sessionid = "sid"
        self.access_token = "at"
        self.device_id = "DEV"
        self.old_device_id = "DEV"
        self.device_profile = {}
        self.read_templates = {}
        self.cookie_str = ""

    def ensure_client_session(self):
        self.raised += 1
        return "CLIENT"

    def ensure_fresh(self, *a, **kw):
        return None

    def _call_read(self, key, *, overrides=None, body=None, path_override=None):
        self._ensure_level_for(key)
        self.seen.append(key)
        self.raised_before[key] = self.raised
        return {"payload": {}}

    def _call_signed(self, key, body_str, extra_query=None):
        self._ensure_level_for(key)
        self.seen.append(key)
        self.raised_before[key] = self.raised
        return {"payload": {"paymentId": "1"}}


# ── каждая точка входа в шлюз поднимает уровень ─────────────────────────────
GATE = ["v1_pay", "payment_commission", "payment_gate_pay", "payment_gate_pay_mobile"]

for key in GATE:
    s = Spy()
    if key == "v1_pay":
        s._call_signed(key, "payParameters=%7B%7D")
    else:
        s._call_read(key, body={})
    check(s.raised_before.get(key) == 1,
          f"{key}: уровень не поднят перед запросом — протухший sessionid даст "
          f"403 Forbidden, и это будет выглядеть как авария банка")

# ── обычное чтение лишнего пинга не платит ──────────────────────────────────
for key in ("accounts", "operations", "ping", "session_status", "cars"):
    s = Spy()
    s._call_read(key)
    check(s.raised == 0,
          f"{key}: обычное чтение живёт на Bearer и не должно стоить лишнего "
          f"ping — иначе каждый список счетов дороже вдвое")

# ── список закрыт от опечаток ───────────────────────────────────────────────
check(MobileSession._CLIENT_LEVEL_TEMPLATES == frozenset(GATE),
      f"набор шлюзовых шаблонов разошёлся с тестом: "
      f"{sorted(MobileSession._CLIENT_LEVEL_TEMPLATES)}")

# ── реальные методы клиента идут через ту же дверь ──────────────────────────
s = Spy()
s.payment_commission({"payParameters": {"moneyAmount": 1}})
check(s.raised == 1,
      "payment_commission не поднял уровень — а это первый вызов, на котором "
      "ловится закрывшееся окно, и он не стоит ни копейки")

s = Spy()
s.pay("payParameters=%7B%7D")
check(s.raised == 1, "pay() не поднял уровень — это и есть тот самый платёж")

# ── ensure_client_session не зациклится на собственном ping ─────────────────
check("ping" not in MobileSession._CLIENT_LEVEL_TEMPLATES,
      "ping попал в список шлюзовых — ensure_client_session вызывает его сам, "
      "получится бесконечная рекурсия на первом же платеже")

if failures:
    print("ПРОВАЛЫ:")
    for f in failures:
        print("  -", f)
    sys.exit(1)
print("payment gate: ок — денежный путь поднимает сессию до CLIENT, чтения не платят")
