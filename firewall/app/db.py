"""Хранилище фаервола: SQLite и ничего больше.

Без ORM намеренно. Вся схема — семь таблиц, из которых по-настоящему растёт одна
(`requests`), а решение о переводе денег должно приниматься кодом, который целиком
читается за один присест. Плюс SQLite = один файл в volume: бэкап политики — это
`cp`, а не дамп.

ЖУРНАЛ И СЕКРЕТЫ. `requests.args_json` — то, что агент реально передал, и это
основной материал для разбора «почему заблокировали». Пароли, PIN, OTP и
платёжные токены (`catalog.SECRET_ARGS`) в него не попадают ВООБЩЕ: пишется
факт наличия аргумента и его длина. Всё остальное сохраняется как есть —
получателя и сумму скрывать от владельца его же фаервола незачем, а без них
журнал не отвечает на вопрос, ради которого заведён.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

DB_PATH = os.environ.get("TBANK_FW_DB", os.path.join(os.getcwd(), "data", "firewall.db"))

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    priority    INTEGER NOT NULL DEFAULT 100,
    action      TEXT NOT NULL,              -- allow | deny | hitl
    match_json  TEXT NOT NULL DEFAULT '{}',
    hitl_mode   TEXT NOT NULL DEFAULT '',   -- '' = взять из настроек
    skip_limits INTEGER NOT NULL DEFAULT 0,
    reason      TEXT NOT NULL DEFAULT '',
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS lists (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'recipients',
    entries_json TEXT NOT NULL DEFAULT '[]',
    note        TEXT NOT NULL DEFAULT '',
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS limits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    match_json  TEXT NOT NULL DEFAULT '{}',
    window      TEXT NOT NULL DEFAULT 'day', -- tx | hour | day | week | month
    max_amount  REAL,
    max_count   INTEGER,
    on_exceed   TEXT NOT NULL DEFAULT 'deny',
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_modes (
    tool TEXT PRIMARY KEY,
    mode TEXT NOT NULL              -- on | blocked | hidden
);

CREATE TABLE IF NOT EXISTS requests (
    id            TEXT PRIMARY KEY,
    ts            REAL NOT NULL,
    agent         TEXT NOT NULL DEFAULT '',
    session       TEXT NOT NULL DEFAULT '',
    tool          TEXT NOT NULL,
    kind          TEXT NOT NULL,
    category      TEXT NOT NULL DEFAULT '',
    args_json     TEXT NOT NULL DEFAULT '{}',
    facets_json   TEXT NOT NULL DEFAULT '{}',
    amount        REAL,
    recipient     TEXT NOT NULL DEFAULT '',
    org           TEXT NOT NULL DEFAULT '',
    card          TEXT NOT NULL DEFAULT '',
    from_account  TEXT NOT NULL DEFAULT '',
    decision      TEXT NOT NULL,            -- allow | deny | hitl
    status        TEXT NOT NULL,            -- allowed|denied|pending|executed|failed|expired
    rule_id       INTEGER,
    rule_name     TEXT NOT NULL DEFAULT '',
    reason        TEXT NOT NULL DEFAULT '',
    sig           TEXT NOT NULL DEFAULT '',
    result_ts     REAL,
    result_status TEXT NOT NULL DEFAULT '',
    ms            INTEGER,
    output_head   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts DESC);
CREATE INDEX IF NOT EXISTS idx_requests_sig ON requests(sig);
CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status);

-- Реквизиты СБП, которые банк ДЕЙСТВИТЕЛЬНО вернул на transfer_sbp_resolve.
-- Существует ради одной проверки: перевод не должен уходить по маршруту, который
-- агент придумал сам. Это не кэш — по этим строкам ничего не подставляется,
-- только сверяется присланное.
CREATE TABLE IF NOT EXISTS resolved_requisites (
    recipient       TEXT NOT NULL,
    bank_member_id  TEXT NOT NULL,
    pointer_link_id TEXT NOT NULL,
    bank_name       TEXT NOT NULL DEFAULT '',
    masked_fio      TEXT NOT NULL DEFAULT '',
    ts              REAL NOT NULL,
    PRIMARY KEY (recipient, bank_member_id, pointer_link_id)
);
CREATE INDEX IF NOT EXISTS idx_req_recipient ON resolved_requisites(recipient);

-- Выбор банка получателя кликом. Заводится, когда у номера несколько банков СБП
-- и решать должен человек, а не модель. Здесь же лежат реквизиты кандидатов,
-- полученные РЕЗОЛВОМ ВНУТРИ transfer(): он идёт мимо тула transfer_sbp_resolve,
-- поэтому иначе фаервол про них не узнаёт и потом сам же их отвергает.
CREATE TABLE IF NOT EXISTS choices (
    id           TEXT PRIMARY KEY,
    created_at   REAL NOT NULL,
    expires_at   REAL NOT NULL,
    state        TEXT NOT NULL DEFAULT 'pending',  -- pending|picked|cancelled|expired
    recipient    TEXT NOT NULL DEFAULT '',
    amount       REAL,
    from_account TEXT NOT NULL DEFAULT '',
    agent        TEXT NOT NULL DEFAULT '',
    candidates_json TEXT NOT NULL DEFAULT '[]',
    chosen_json  TEXT NOT NULL DEFAULT '',
    decided_at   REAL
);
CREATE INDEX IF NOT EXISTS idx_choices_state ON choices(state);

CREATE TABLE IF NOT EXISTS hitl (
    request_id TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    state      TEXT NOT NULL DEFAULT 'pending',  -- pending|approved|denied|expired
    mode       TEXT NOT NULL DEFAULT 'async',
    sig        TEXT NOT NULL DEFAULT '',
    decided_at REAL,
    decided_by TEXT NOT NULL DEFAULT '',
    note       TEXT NOT NULL DEFAULT '',
    consumed_at REAL
);
CREATE INDEX IF NOT EXISTS idx_hitl_state ON hitl(state);
CREATE INDEX IF NOT EXISTS idx_hitl_sig ON hitl(sig);
"""

DEFAULT_SETTINGS = {
    # Политика по умолчанию, когда ни одно правило не совпало. Чтение разрешено,
    # всё остальное спрашивает человека: незнакомое действие с деньгами не должно
    # проходить только потому, что правило под него ещё не написали.
    "default_read": "allow",
    "default_write": "allow",
    "default_money": "hitl",
    # async — вернуть агенту ссылку и не держать вызов; wait — подождать решения
    # в самом вызове (агент видит обычный ответ тула, человек успевает нажать).
    "hitl_mode": "async",
    "hitl_ttl_sec": "900",
    "hitl_wait_sec": "120",
    "base_url": "http://localhost:8080",
    # Демон входа. Живёт НА ХОСТЕ рядом с MCP, а не в этом контейнере: сессия
    # банка должна лечь туда, откуда её читает MCP, и пароль не должен проходить
    # через фаервол вообще. Браузер ходит туда напрямую — см. templates/auth.html.
    "authd_url": "http://127.0.0.1:8765",
    # Маскирование того, что уходит ОБРАТНО агенту.
    "mask_pan": "1",
    "mask_rules_json": "[]",
    # Не пускать перевод по реквизитам СБП, которых банк не возвращал. Модель,
    # у которой не получилось их узнать, склонна подставить правдоподобные
    # цифры — и это уже случалось: перевод ушёл по выдуманному bankMemberId и
    # получил 403. Проверяется по журналу transfer_sbp_resolve.
    "require_resolved_requisites": "1",
    # Сколько секунд реквизиты СБП считаются свежими. Банк перевыпускает
    # pointerLinkId: два резолва одного номера в один банк с разницей в минуты
    # дали разные связки. По устаревшей платёж не пройдёт, поэтому старую запись
    # проверка не принимает и отправляет агента за свежей.
    "requisites_ttl_sec": "1800",
    "ui_title": "Bank AI Firewall",
}


def connect() -> sqlite3.Connection:
    """Соединение на поток. FastAPI гоняет sync-эндпоинты в threadpool, а
    sqlite3-соединение нельзя делить между потоками."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
        conn = sqlite3.connect(DB_PATH, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        _local.conn = conn
    return conn


# Колонки, добавленные после первого релиза. CREATE TABLE IF NOT EXISTS не трогает
# уже существующую таблицу, а база живёт в volume и переживает пересборку образа —
# поэтому новые поля доезжают сюда, а не в SCHEMA.
MIGRATIONS: dict[str, dict[str, str]] = {
    "rules": {
        # Квота правила: «разрешать, но не больше N раз / N ₽ в окно, дальше —
        # на подтверждение». Живёт на самом правиле, а не отдельным лимитом,
        # потому что иначе разрешающее правило и его норму надо держать
        # синхронными руками, и рассинхрон замечают уже по факту.
        "quota_window": "TEXT NOT NULL DEFAULT ''",
        "quota_max_count": "INTEGER",
        "quota_max_amount": "REAL",
        "quota_on_exceed": "TEXT NOT NULL DEFAULT 'hitl'",
    },
}


def _migrate(conn: sqlite3.Connection) -> None:
    for table, columns in MIGRATIONS.items():
        have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        for name, decl in columns.items():
            if name not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


def init() -> None:
    conn = connect()
    conn.executescript(SCHEMA)
    _migrate(conn)
    for k, v in DEFAULT_SETTINGS.items():
        conn.execute("INSERT OR IGNORE INTO settings(key, value) VALUES (?,?)", (k, v))
    conn.commit()


# ── настройки ────────────────────────────────────────────────────────────────

def settings() -> dict[str, str]:
    rows = connect().execute("SELECT key, value FROM settings").fetchall()
    out = dict(DEFAULT_SETTINGS)
    out.update({r["key"]: r["value"] for r in rows})
    return out


def get_setting(key: str, default: str = "") -> str:
    row = connect().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    if row is not None:
        return row["value"]
    return DEFAULT_SETTINGS.get(key, default)


def set_setting(key: str, value: str) -> None:
    conn = connect()
    conn.execute(
        "INSERT INTO settings(key, value) VALUES (?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)),
    )
    conn.commit()


# ── мелкие помощники ─────────────────────────────────────────────────────────

def rows(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    return connect().execute(sql, params).fetchall()


def one(sql: str, params: tuple = ()) -> sqlite3.Row | None:
    return connect().execute(sql, params).fetchone()


def run(sql: str, params: tuple = ()) -> sqlite3.Cursor:
    conn = connect()
    cur = conn.execute(sql, params)
    conn.commit()
    return cur


def jload(text: str, fallback):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return fallback
