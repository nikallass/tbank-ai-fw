"""Локальный демон входа: форма живёт в вебморде, сессия — здесь, на хосте.

ЗАЧЕМ ОН ЕСТЬ.
Войти в банк можно тремя способами, и все три плохи по-своему:
  • `login_cli.py` — пароль не утекает никуда, но это терминал, getpass и
    три шага вслепую;
  • через агента (`login`/`confirm_otp`/`confirm_password`) — удобно, но пароль
    оказывается в контексте модели и в логах клиента;
  • класть сессию в вебморду — тогда контейнер начинает хранить доступ к деньгам,
    а этого не хочет никто.

Поэтому вход разложен надвое. Форму рисует вебморда фаервола, а браузер шлёт
введённое НАПРЯМУЮ сюда, минуя контейнер: пароль не проходит через фаервол и не
появляется в его журнале. Сессия ложится ровно туда, откуда её читает MCP —
`~/.local/share/tbank-mcp/session.json`, 0600. Фаервол о ней не знает ничего.

ГРАНИЦА ДОВЕРИЯ.
Слушает только 127.0.0.1. CORS — жёсткий список источников, и на POST требуется
`Content-Type: application/json`: это делает запрос «непростым» по правилам
браузера, поэтому чужая страница не сможет отправить его без preflight, который
мы ей завернём. Ни один ответ не содержит токенов, куки и введённых значений.

    python -m src.authd            # или bin/tbank-authd
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 127.0.0.1 по умолчанию: на хосте демон не должен быть виден никому снаружи.
# В контейнере это значение бесполезно — петля контейнера не та же, что петля
# хоста, и опубликованный порт до неё не дотягивается, — поэтому compose ставит
# 0.0.0.0. Наружу это ничего не открывает: порт публикуется на 127.0.0.1 хоста.
HOST = os.environ.get("TBANK_AUTHD_HOST", "127.0.0.1")
PORT = int(os.environ.get("TBANK_AUTHD_PORT", "8765"))
ORIGINS = [o.strip() for o in os.environ.get(
    "TBANK_AUTHD_ORIGINS",
    "http://127.0.0.1:8080,http://localhost:8080").split(",") if o.strip()]

# Незавершённый вход живёт только в памяти этого процесса: cid, token и куки
# банка держатся в одном MobileSession, и между шагами его нельзя ни сериализовать,
# ни передать. Перезапуск демона на середине входа = начать заново, и это честнее,
# чем складывать полуготовый логин на диск.
_LOCK = threading.Lock()
_PENDING: dict = {}

_RE_NEXT = re.compile(r"Следующий шаг\s*[—-]\s*'?(\w+)")


def _next_step(hint: str) -> str:
    m = _RE_NEXT.search(hint or "")
    if m and m.group(1) in ("otp", "password", "pin"):
        return m.group(1)
    for step in ("otp", "password", "pin"):
        if step in (hint or "").lower():
            return step
    return ""


def _mask_phone(phone: str) -> str:
    digits = re.sub(r"\D", "", phone or "")
    return f"+{digits[0]}•••••{digits[-4:]}" if len(digits) >= 8 else "•••"


def _srv():
    """Импорт откладывается до первого запроса: src.server поднимает FastMCP и
    спрашивает у фаервола зону видимости, а демону это нужно только когда им
    действительно пользуются."""
    from src import server
    return server


# ── состояние ────────────────────────────────────────────────────────────────

def status(live: bool = False) -> dict:
    srv = _srv()
    path = srv._SESSION_FILE
    out: dict = {
        "session_file": path,
        "exists": os.path.exists(path),
        "state": "none",
        "pending": None,
        "authd_port": PORT,
    }
    with _LOCK:
        if _PENDING:
            out["pending"] = {"next": _PENDING.get("next", ""),
                              "phone": _mask_phone(_PENDING.get("phone", "")),
                              "age_sec": int(time.time() - _PENDING.get("started", 0))}
    if not out["exists"]:
        return out
    try:
        st = os.stat(path)
        out["mode"] = oct(st.st_mode & 0o777)
        out["size"] = st.st_size
        out["mtime"] = st.st_mtime
    except OSError:
        pass

    s = srv._load_session()
    if s is None:
        out["state"] = "broken"
        return out
    minted = getattr(s, "_minted_at", 0) or 0
    out["minted_at"] = minted
    out["age_sec"] = int(time.time() - minted) if minted else None
    out["expires_in"] = getattr(s, "expires_in", 0)
    # Без SSO_SESSION протухший токен уже не восстановить молча — придётся
    # проходить весь вход заново, и человеку стоит знать об этом заранее.
    out["can_silent_relogin"] = bool(getattr(s, "sso_login_cookie", ""))
    out["device_id"] = (getattr(s, "device_id", "") or "")[:8]
    fresh = minted and (time.time() - minted) < max(60, (s.expires_in or 7199) - 600)
    out["state"] = "active" if fresh else "stale"

    if live:
        try:
            srv._with_persist(s)
            s.ensure_client_session()
            raw = s.session_status()
            payload = raw.get("payload", raw) if isinstance(raw, dict) else {}
            out["live"] = {
                "ok": True,
                "access_level": payload.get("accessLevel") or payload.get("access_level"),
                "expires_in": payload.get("expiresIn") or payload.get("ssoExpiresIn"),
            }
            out["state"] = "active"
        except Exception as e:                                   # noqa: BLE001
            out["live"] = {"ok": False, "error": f"{type(e).__name__}: {e}"[:300]}
    return out


def start_login(phone: str) -> dict:
    srv = _srv()
    s = srv._blank_session()
    hint = s.login(phone)
    step = _next_step(hint) or "otp"
    with _LOCK:
        _PENDING.clear()
        _PENDING.update({"session": s, "phone": phone, "next": step,
                         "started": time.time()})
    return {"ok": True, "next": step, "message": hint,
            "phone": _mask_phone(phone)}


def submit_step(kind: str, value: str) -> dict:
    from src.client import TbankApiError
    srv = _srv()
    with _LOCK:
        pending = dict(_PENDING)
    if not pending.get("session"):
        return {"ok": False, "error": "Вход не начат — введите номер телефона заново.",
                "restart": True}
    if kind not in ("otp", "password", "pin"):
        return {"ok": False, "error": f"неизвестный шаг {kind!r}"}
    s = pending["session"]

    try:
        s.confirm_step(kind, value)
    except TbankApiError as e:
        step = _next_step(str(e.message))
        if step:
            with _LOCK:
                _PENDING["next"] = step
            return {"ok": True, "next": step, "message": str(e.message)}
        # Настоящая ошибка: неверный код, истёкшая попытка, блокировка. Это
        # ровно тот текст, который человеку нужно прочитать, поэтому он идёт
        # наверх как есть — введённого значения банк в ответ не кладёт.
        return {"ok": False, "error": f"{e.result_code}: {e.message}"[:300]}
    except Exception as e:                                       # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"[:300]}

    if not s.access_token:
        with _LOCK:
            _PENDING["next"] = "password"
        return {"ok": True, "next": "password",
                "message": "Банк ждёт следующий шаг."}

    srv._session = srv._with_persist(s)
    srv._save_session(s)
    with _LOCK:
        _PENDING.clear()
    return {"ok": True, "done": True, "session_file": srv._SESSION_FILE,
            "message": "Сессия сохранена. Агент возьмёт её сам, пароль ему не нужен."}


def cancel() -> dict:
    with _LOCK:
        _PENDING.clear()
    return {"ok": True}


def logout() -> dict:
    srv = _srv()
    path = srv._SESSION_FILE
    existed = os.path.exists(path)
    if existed:
        os.remove(path)
    srv._session = None
    with _LOCK:
        _PENDING.clear()
    return {"ok": True, "removed": existed, "session_file": path}


# ── HTTP ─────────────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    server_version = "tbank-authd"

    def log_message(self, fmt, *args):
        # Путь и метод — да; тела с паролем в лог не попадает ничего.
        sys.stderr.write(f"[authd] {self.address_string()} {fmt % args}\n")

    # ── ответы ──────────────────────────────────────────────────────────────
    def _cors(self):
        origin = self.headers.get("Origin", "")
        if origin in ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Max-Age", "600")
            return True
        return False

    def _send(self, obj, code: int = 200):
        body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204 if self._is_allowed_origin() else 403)
        self._cors()
        self.end_headers()

    def _is_allowed_origin(self) -> bool:
        origin = self.headers.get("Origin")
        # Запрос без Origin — это curl или наш же скрипт с этой машины, не браузер.
        return origin is None or origin in ORIGINS

    def do_GET(self):
        if not self._is_allowed_origin():
            return self._send({"error": "origin не разрешён"}, 403)
        path = self.path.split("?")[0]
        if path == "/api/auth/status":
            live = "live=1" in self.path
            try:
                return self._send(status(live=live))
            except Exception as e:                               # noqa: BLE001
                return self._send({"error": f"{type(e).__name__}: {e}"[:300]}, 500)
        if path in ("/", "/health"):
            return self._send({"ok": True, "service": "tbank-authd", "port": PORT})
        return self._send({"error": "not found"}, 404)

    def do_POST(self):
        if not self._is_allowed_origin():
            return self._send({"error": "origin не разрешён"}, 403)
        # Требование JSON — это защита, а не формальность: «простой» POST формой
        # браузер отправляет без preflight, и чужая вкладка могла бы дёрнуть
        # /logout или разослать SMS. С application/json preflight обязателен.
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if ctype != "application/json":
            return self._send({"error": "нужен Content-Type: application/json"}, 415)
        try:
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            payload = json.loads(raw or b"{}")
        except ValueError:
            return self._send({"error": "тело не JSON"}, 400)

        path = self.path.split("?")[0]
        try:
            if path == "/api/auth/login":
                phone = str(payload.get("phone", "")).strip()
                if not phone:
                    return self._send({"ok": False, "error": "не указан телефон"}, 400)
                return self._send(start_login(phone))
            if path == "/api/auth/step":
                return self._send(submit_step(str(payload.get("kind", "")),
                                              str(payload.get("value", ""))))
            if path == "/api/auth/cancel":
                return self._send(cancel())
            if path == "/api/auth/logout":
                return self._send(logout())
        except Exception as e:                                   # noqa: BLE001
            # Текст ошибки банка полезен человеку; введённого значения в нём нет.
            return self._send({"ok": False, "error": f"{type(e).__name__}: {e}"[:300]}, 500)
        return self._send({"error": "not found"}, 404)


def main() -> None:
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[authd] вход слушает http://{HOST}:{PORT}", file=sys.stderr)
    print(f"[authd] источники: {', '.join(ORIGINS)}", file=sys.stderr)
    print(f"[authd] форма входа: {ORIGINS[0] if ORIGINS else ''}/auth", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[authd] остановлен", file=sys.stderr)


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    main()
