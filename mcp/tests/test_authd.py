"""Демон входа: шаги логина, границы доверия, куда ложится сессия.

Банк здесь не участвует — MobileSession подменён. Проверяется ровно то, ради чего
демон отделён от вебморды: пароль принимает ЭТОТ процесс, сессия ложится в файл
MCP с правами 0600, и ни одно введённое значение не возвращается наружу.

    .venv/bin/python tests/test_authd.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import types
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src import authd                                            # noqa: E402
from src.client import TbankApiError                             # noqa: E402

failures: list[str] = []


def check(cond, msg: str) -> None:
    if not cond:
        failures.append(msg)


TMP = tempfile.mkdtemp(prefix="authd-")
SESSION_FILE = os.path.join(TMP, "session.json")
SEEN: list[tuple] = []          # что реально дошло до «банка»


class FakeSession:
    """Первое устройство: otp → password → сессия. Как в настоящем клиенте."""

    def __init__(self):
        self.access_token = ""
        self.expires_in = 7199
        self.device_id = "dev12345678"
        self.sso_login_cookie = ""
        self._minted_at = 0.0

    def login(self, phone):
        SEEN.append(("login", phone))
        return "SMS отправлена. Следующий шаг — otp. Вызови confirm_otp(<код из СМС>)."

    def confirm_step(self, kind, value):
        SEEN.append((kind, value))
        if kind == "otp":
            if value != "1234":
                raise TbankApiError("WRONG_OTP", "неверный код")
            raise TbankApiError("NEXT_STEP",
                                "Следующий шаг — password. Вызови confirm_password(<пароль>).")
        if kind == "password":
            self.access_token = "tok"
            self.sso_login_cookie = "SSO_SESSION=x"
            self._minted_at = __import__("time").time()
            return {}
        raise TbankApiError("UNEXPECTED", kind)


def _save(s):
    fd = os.open(SESSION_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({k: v for k, v in s.__dict__.items()}, fh)


def _load():
    if not os.path.exists(SESSION_FILE):
        return None
    s = FakeSession()
    s.__dict__.update(json.load(open(SESSION_FILE)))
    return s


STUB = types.SimpleNamespace(
    _SESSION_FILE=SESSION_FILE, _session=None,
    _blank_session=FakeSession, _save_session=_save, _load_session=_load,
    _with_persist=lambda s: s,
)
authd._srv = lambda: STUB

httpd = ThreadingHTTPServer(("127.0.0.1", 0), authd.Handler)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{httpd.server_address[1]}"
ORIGIN = authd.ORIGINS[0]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def call(method, path, body=None, origin=ORIGIN, ctype="application/json"):
    headers = {}
    if origin:
        headers["Origin"] = origin
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = ctype
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with opener.open(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw or b"{}")
        except ValueError:
            return e.code, {}


# ── до входа ─────────────────────────────────────────────────────────────────
_, st = call("GET", "/api/auth/status")
check(st["state"] == "none", f"пустое состояние прочитано неверно: {st}")
check(st["session_file"] == SESSION_FILE, "демон смотрит не в тот файл сессии")
check(st["pending"] is None, "на старте не должно быть незавершённого входа")

# ── шаг 1: телефон ───────────────────────────────────────────────────────────
_, r = call("POST", "/api/auth/login", {"phone": "+79991234567"})
check(r["ok"] is True and r["next"] == "otp", f"шаг после телефона неверен: {r}")
check("9991234567" not in json.dumps(r, ensure_ascii=False),
      f"телефон вернулся в ответе целиком: {r}")

_, st = call("GET", "/api/auth/status")
check(st["pending"]["next"] == "otp", "незавершённый вход не виден в статусе")

# ── шаг 2: неверный код не двигает вход дальше ───────────────────────────────
code, r = call("POST", "/api/auth/step", {"kind": "otp", "value": "0000"})
check(r["ok"] is False, "неверный код принят как верный")
check("0000" not in json.dumps(r, ensure_ascii=False), "введённый код вернулся в ответе")
# Человеку нужен текст банка, а не питоновская ошибка: именно по нему видно,
# что код неверный, а не что вход сломался.
check(code == 200, f"отказ банка отдан как сбой сервера: HTTP {code}")
check("неверный код" in r.get("error", ""),
      f"сообщение банка потерялось по дороге: {r.get('error')!r}")
_, st_mid = call("GET", "/api/auth/status")
check(st_mid["pending"]["next"] == "otp", "после неверного кода вход должен ждать код")

# ── шаг 2: верный код ведёт к паролю ─────────────────────────────────────────
_, r = call("POST", "/api/auth/step", {"kind": "otp", "value": "1234"})
check(r.get("next") == "password", f"после кода банк должен просить пароль: {r}")

# ── шаг 3: пароль создаёт сессию ─────────────────────────────────────────────
_, r = call("POST", "/api/auth/step", {"kind": "password", "value": "s3cret"})
check(r.get("done") is True, f"вход не завершился: {r}")
check("s3cret" not in json.dumps(r, ensure_ascii=False), "ПАРОЛЬ ВЕРНУЛСЯ В ОТВЕТЕ")
check(("password", "s3cret") in SEEN, "пароль не дошёл до клиента банка")

check(os.path.exists(SESSION_FILE), "session.json не создан")
check(oct(os.stat(SESSION_FILE).st_mode & 0o777) == "0o600",
      f"права на session.json не 0600: {oct(os.stat(SESSION_FILE).st_mode & 0o777)}")

_, st = call("GET", "/api/auth/status")
check(st["state"] == "active", f"сессия не считается активной: {st}")
check(st["can_silent_relogin"] is True, "SSO_SESSION не учтён")
check(st["pending"] is None, "после входа не должно остаться незавершённого шага")
check("tok" not in json.dumps(st, ensure_ascii=False), "ТОКЕН ОТДАН НАРУЖУ В СТАТУСЕ")

# ── границы доверия ──────────────────────────────────────────────────────────
code, _ = call("OPTIONS", "/api/auth/login", origin="https://evil.example")
check(code == 403, f"preflight с чужого источника не отклонён: {code}")

code, _ = call("POST", "/api/auth/logout", {"x": 1}, origin="https://evil.example")
check(code == 403, f"POST с чужого источника выполнен: {code}")
check(os.path.exists(SESSION_FILE), "чужая страница успела удалить сессию")

# Форма без preflight — то, чем чужая вкладка могла бы дёрнуть демон вслепую.
code, _ = call("POST", "/api/auth/logout", {"x": 1},
               ctype="application/x-www-form-urlencoded")
check(code == 415, f"простой POST формой не отклонён: {code}")
check(os.path.exists(SESSION_FILE), "сессия удалена простым POST-ом формы")

# ── выход ────────────────────────────────────────────────────────────────────
_, r = call("POST", "/api/auth/logout", {})
check(r["removed"] is True, "выход не удалил сессию")
check(not os.path.exists(SESSION_FILE), "session.json остался на диске после выхода")

# ── шаг без начатого входа ───────────────────────────────────────────────────
_, r = call("POST", "/api/auth/step", {"kind": "otp", "value": "1234"})
check(r["ok"] is False and r.get("restart") is True,
      f"шаг без начатого входа должен просить начать заново: {r}")

httpd.shutdown()

if failures:
    print("ПРОВАЛЫ:")
    for f in failures:
        print("  -", f)
    sys.exit(1)
print("authd: ок — пароль не возвращается, сессия 0600, чужой источник отклонён")
