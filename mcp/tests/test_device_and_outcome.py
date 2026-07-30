"""Одно устройство на сессию, и «отказ» отличается от «неизвестно».

Две вещи, которые стоили живого платежа:

  1. Блоб устройства при ВХОДЕ и блок антифрода при ОПЛАТЕ описывали разные
     телефоны — 1170×2532 в Москве против 1260×2736 на Кипре, в одной сессии
     с одним deviceId. /v1/pay отвечал 403, а все чтения работали.
  2. HTTP 403 записывался как «ИСХОД НЕИЗВЕСТЕН»: пользователю сообщали, что
     деньги могли уйти, и повтор блокировался защитой от дублей — на платеже,
     который банк открыто отверг.

    .venv/bin/python tests/test_device_and_outcome.py
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.setdefault("TBANK_FIREWALL", "0")

import requests                                                   # noqa: E402

from src import client as cl                                      # noqa: E402
from src import server as srv                                     # noqa: E402
from src.client import MobileSession, SessionExpired, TbankApiError  # noqa: E402

failures: list[str] = []


def check(cond, msg: str) -> None:
    if not cond:
        failures.append(msg)


DEVICE_ENV = ("TBANK_DEVICE_SCREEN_WIDTH", "TBANK_DEVICE_SCREEN_HEIGHT",
              "TBANK_DEVICE_LANGUAGE", "TBANK_DEVICE_TIMEZONE",
              "TBANK_DEVICE_TIMEZONE_NAME")


def fingerprint(**env) -> dict:
    saved = {k: os.environ.get(k) for k in DEVICE_ENV}
    for k in DEVICE_ENV:
        os.environ.pop(k, None)
    os.environ.update({k: str(v) for k, v in env.items()})
    try:
        return json.loads(cl._builtin_fingerprint("DEV-1"))
    finally:
        for k in DEVICE_ENV:
            os.environ.pop(k, None)
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v


# ── БЕЗ НАСТРОЕК вход и оплата описывают ОДИН захваченный айфон ─────────────
# Это главная проверка файла. Раньше здесь было два независимых набора констант,
# и они разошлись: вход синтезировал 1170×2532 с языком ru, платёж посылал
# захваченные 1260×2736 с ru-CY. Ничего настраивать не нужно, чтобы это сошлось.
base = fingerprint()
shipped_pay = MobileSession("sid", "rt").PAY_DEVICE_PROFILE
check(base["screenResolution"] ==
      f"{shipped_pay['device_screen_width']}*{shipped_pay['device_screen_height']}",
      f"вход и оплата снова про разные экраны: {base['screenResolution']} vs "
      f"{shipped_pay['device_screen_width']}*{shipped_pay['device_screen_height']}")
check(shipped_pay["language"].startswith(base["language"]),
      f"вход и оплата про разные языки: {base['language']} vs {shipped_pay['language']}")

# Значения — из захвата, а не выдуманные. Пинится, чтобы «почистить» их случайно
# было нельзя: это факты живого приложения, сверенные с captures.xml.
check(base["screenResolution"] == "1260*2736",
      f"захваченный экран подменили: {base['screenResolution']}")
check((base["screenWidth"], base["screenHeight"]) == (420, 912),
      f"точки посчитаны неверно: {base['screenWidth']}×{base['screenHeight']}")
check(shipped_pay["language"] == "ru-CY",
      f"захваченная локаль подменена: {shipped_pay['language']}")
check(base["language"] == "ru", f"язык блоба входа поехал: {base['language']}")
check(base["timeZoneName"] == "Europe/Moscow",
      f"пояс по умолчанию поехал: {base['timeZoneName']}")
check(cl.CAPTURED_DEVICE["timezone"] == shipped_pay["timezone"] == "180",
      "пояс оплаты разошёлся с захватом")

# ── настройки доезжают до блоба входа ───────────────────────────────────────
got = fingerprint(TBANK_DEVICE_SCREEN_WIDTH=1179, TBANK_DEVICE_SCREEN_HEIGHT=2556,
                  TBANK_DEVICE_LANGUAGE="ru-RU")
check(got["screenResolution"] == "1179*2556",
      f"экран не доехал до блоба входа: {got['screenResolution']}")
check((got["screenWidth"], got["screenHeight"]) == (393, 852),
      f"точки посчитаны неверно: {got['screenWidth']}×{got['screenHeight']}")
check(got["language"] == "ru", f"локаль ru-RU должна стать языком ru: {got['language']}")
check(fingerprint(TBANK_DEVICE_LANGUAGE="en-US")["language"] == "en",
      "язык не выделяется из локали")

# ── настроенный телефон тоже остаётся ОДНИМ телефоном ───────────────────────
# Тот, кто описывает свой аппарат, не должен получить починенный платёж и
# разъехавшийся логин.
saved = {k: os.environ.get(k) for k in DEVICE_ENV}
os.environ.update({"TBANK_DEVICE_SCREEN_WIDTH": "1179",
                   "TBANK_DEVICE_SCREEN_HEIGHT": "2556",
                   "TBANK_DEVICE_LANGUAGE": "ru-RU",
                   "TBANK_DEVICE_TIMEZONE": "180"})
try:
    fp = json.loads(cl._builtin_fingerprint("DEV-1"))
    pay = MobileSession("sid", "rt").PAY_DEVICE_PROFILE
    check(fp["screenResolution"] == f"{pay['device_screen_width']}*{pay['device_screen_height']}",
          f"настроенные вход и оплата про разные экраны: {fp['screenResolution']} "
          f"vs {pay['device_screen_width']}*{pay['device_screen_height']}")
    check(pay["language"].startswith(fp["language"]),
          f"настроенные вход и оплата про разные языки: {fp['language']} vs {pay['language']}")
    check(pay["timezone"] == "180" and fp["timeZoneName"] == "Europe/Moscow",
          f"вход и оплата про разные пояса: {fp['timeZoneName']} vs {pay['timezone']}")
finally:
    for k in DEVICE_ENV:
        os.environ.pop(k, None)
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v

# Один источник фактов, а не два синхронизируемых руками.
check(MobileSession("sid", "rt").PAY_DEVICE_DEFAULTS == cl.CAPTURED_DEVICE,
      "блок оплаты снова живёт своим набором констант")
check(MobileSession("sid", "rt").PAY_DEVICE_DEFAULTS is not cl.CAPTURED_DEVICE,
      "PAY_DEVICE_DEFAULTS ссылается на общий словарь — переопределение сессии "
      "испортит его для всех")

# ── вход через нашу вебморду использует тот же телефон ──────────────────────
# `authd` и `login_cli` оба берут сессию из server._blank_session(), поэтому
# описание устройства у них не своё — но проверить это дешевле, чем однажды
# обнаружить, что вход из вебморды представляется иначе, чем вход из терминала.
fresh = srv._blank_session()
fp_login = json.loads(fresh.fingerprint)
fp_step = json.loads(fresh.auth_step_fingerprint)
check(fp_login["screenResolution"] == "1260*2736",
      f"вход из вебморды описывает другой телефон: {fp_login['screenResolution']}")
check(fp_step["screenResolution"] == fp_login["screenResolution"],
      "fingerprint и auth_step_fingerprint разошлись между собой")
check(fp_login["language"] == "ru" and fp_login["timeZoneName"] == "Europe/Moscow",
      f"локаль/пояс входа поехали: {fp_login['language']}, {fp_login['timeZoneName']}")
check(fresh.PAY_DEVICE_PROFILE["device_screen_width"] == "1260",
      "платёж из этой же сессии описывает другой телефон")

# ── отказ банка ≠ неизвестный исход ─────────────────────────────────────────
def http_error(status: int) -> requests.exceptions.HTTPError:
    resp = requests.Response()
    resp.status_code = status
    return requests.exceptions.HTTPError(f"{status} Client Error", response=resp)


check(srv._bank_refused(http_error(403)) is True,
      "403 от /v1/pay всё ещё читается как «деньги могли уйти»")
check(srv._bank_refused(http_error(400)) is True, "400 должен считаться отказом")
check(srv._bank_refused(http_error(401)) is True, "401 должен считаться отказом")
check(srv._bank_refused(http_error(404)) is True, "404 должен считаться отказом")

# Здесь запрос мог быть принят и отложен — исход честно неизвестен.
check(srv._bank_refused(http_error(408)) is False, "408 — это неизвестность")
check(srv._bank_refused(http_error(429)) is False, "429 — это неизвестность")
check(srv._bank_refused(http_error(500)) is False, "5xx — это неизвестность")
check(srv._bank_refused(http_error(502)) is False, "502 — это неизвестность")

# Обрыв связи — единственная настоящая неизвестность.
check(srv._bank_refused(requests.exceptions.ConnectionError("reset")) is False,
      "обрыв связи не может быть отказом")
check(srv._bank_refused(requests.exceptions.ReadTimeout("timeout")) is False,
      "таймаут не может быть отказом")

# Конверт ошибки от банка — запрос разобран и отвергнут.
check(srv._bank_refused(TbankApiError("INTERNAL_ERROR", "сервис недоступен")) is True,
      "конверт ошибки банка — это отказ, деньги на месте")
check(srv._bank_refused(SessionExpired("EXPIRED", "re-login")) is True,
      "истёкшая сессия — отказ до отправки денег")


# ── не-JSON ответ: текст шлюза сохраняется, код решает исход ─────────────────
class FakeResp:
    def __init__(self, status, text, reason=""):
        self.status_code, self.text, self.reason = status, text, reason

    def json(self):
        raise ValueError("not json")


def unwrap(status, text, reason=""):
    try:
        MobileSession("sid", "rt")._unwrap(FakeResp(status, text, reason))
    except Exception as e:                                        # noqa: BLE001
        return e
    return None


e = unwrap(403, "<html>Access denied by edge gateway, ref 8842</html>")
check(isinstance(e, TbankApiError), f"не-JSON ответ должен стать TbankApiError: {type(e)}")
check("8842" in str(e), f"ТЕЛО ОТВЕТА ПОТЕРЯНО, отказ снова необъясним: {e}")
check(getattr(getattr(e, "response", None), "status_code", 0) == 403,
      "код ответа не доехал до вызывающего")
check(srv._bank_refused(e) is True, "403 от шлюза — отказ, деньги на месте")

# 5xx без JSON приходит тем же путём и обязан остаться неизвестностью.
e5 = unwrap(502, "<html>Bad gateway</html>")
check(srv._bank_refused(e5) is False,
      "не-JSON 502 записан как отказ — а запрос мог быть принят")

# Пустое тело не должно превращаться в пустое сообщение.
e_empty = unwrap(403, "", reason="Forbidden")
check("Forbidden" in str(e_empty), f"пустой ответ остался без объяснения: {e_empty}")

if failures:
    print("ПРОВАЛЫ:")
    for f in failures:
        print("  -", f)
    sys.exit(1)
print("device+outcome: ок — одно устройство на сессию, 4xx это отказ, а не неизвестность")
