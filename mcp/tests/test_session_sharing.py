"""Файл сессии — общий, и держателей у него больше одного.

Демон входа (в т.ч. в контейнере) и сам MCP работают с одним session.json.
Любое обновление РОТИРУЕТ refresh_token, поэтому тот, кто держит копию в
памяти, после чужого обновления сидит с истраченным токеном: его refresh не
проходит, клиент откатывается на silent_relogin, уровень сессии падает — и
наружу это выглядит как INSUFFICIENT_PRIVILEGES на обычном чтении счетов,
при том что страница входа показывает «сессия активна».

    .venv/bin/python tests/test_session_sharing.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix="sess-")
os.environ["TBANK_SESSION"] = os.path.join(TMP, "session.json")
os.environ["TBANK_FIREWALL"] = "0"
os.environ["TBANK_TRACE"] = "0"

from src import server as srv                                    # noqa: E402

failures: list[str] = []


def check(cond, msg: str) -> None:
    if not cond:
        failures.append(msg)


def write_session(token: str) -> None:
    """Так пишет сессию любой держатель — демон входа или другой процесс."""
    s = srv._blank_session()
    s.mobile_sessionid = "sid-" + token
    s.refresh_token = token
    s.access_token = "at-" + token
    s._minted_at = time.time()
    srv._save_session(s)


# ── первый вызов поднимает сессию с диска ───────────────────────────────────
write_session("token-1")
srv._session = None
check(srv._require().refresh_token == "token-1",
      "сессия не поднялась с диска при первом вызове")

# ── чужое обновление подхватывается ─────────────────────────────────────────
# Мтайм у файловых систем бывает секундной точности — сдвигаем явно, иначе
# тест проверял бы удачу, а не поведение.
time.sleep(0.01)
write_session("token-2")
os.utime(srv._SESSION_FILE, (time.time() + 2, time.time() + 2))
got = srv._require().refresh_token
check(got == "token-2",
      f"MCP остался со старым токеном после чужого обновления: {got!r} — "
      f"именно так и получается INSUFFICIENT_PRIVILEGES при живой сессии")

# ── своя запись не заставляет перечитывать файл ─────────────────────────────
live = srv._require()
live.refresh_token = "token-3-in-memory"
srv._save_session(live)
same = srv._require()
check(same is live,
      "после собственного сохранения сессия перечитана с диска — объект подменился, "
      "а на нём висит _on_persist и незаписанное состояние")
check(same.refresh_token == "token-3-in-memory",
      f"собственное изменение потерялось при перечитывании: {same.refresh_token!r}")

# ── битый файл не роняет живую сессию ───────────────────────────────────────
before = srv._require().refresh_token
with open(srv._SESSION_FILE, "w", encoding="utf-8") as fh:
    fh.write("{ это не json")
os.utime(srv._SESSION_FILE, (time.time() + 5, time.time() + 5))
after = srv._require().refresh_token
check(after == before,
      "битый файл сессии обнулил рабочую сессию — лучше доработать на старой, "
      "чем потерять доступ из-за половины записи")

# ── отсутствие файла не роняет процесс ──────────────────────────────────────
os.remove(srv._SESSION_FILE)
try:
    srv._require()
except Exception as e:                                           # noqa: BLE001
    failures.append(f"пропавший файл уронил _require: {type(e).__name__}: {e}")

if failures:
    print("ПРОВАЛЫ:")
    for f in failures:
        print("  -", f)
    sys.exit(1)
print("session sharing: ок — чужое обновление подхватывается, своё не перечитывается")
