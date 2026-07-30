"""Аргументы тула → факты, по которым срабатывают правила.

Правило пишется словами «получатель», «сумма», «счёт списания». В вызове это
`to_account`, `expected_sum`, `account_id` — разные имена в каждом туле. Перевод
между ними целиком здесь; движок правил про имена аргументов не знает ничего.

Нормализация телефона — не косметика. Один и тот же человек приходит как
`+7 999 123-45-67`, `89991234567` и `79991234567`, и белый список, который
ловит одну запись из трёх, хуже отсутствующего: он создаёт ощущение защиты.
Всё, что похоже на российский номер, приводится к `+7XXXXXXXXXX`.
"""
from __future__ import annotations

import hashlib
import json
import re

from .catalog import FACET_MAP, SECRET_ARGS, category_of, kind_of

_RE_NON_DIGIT = re.compile(r"[^\d+]")


def norm_phone(value: str) -> str:
    """`+7XXXXXXXXXX` для всего, что является российским номером. Иначе — как есть."""
    raw = _RE_NON_DIGIT.sub("", str(value or ""))
    digits = raw.lstrip("+")
    if len(digits) == 11 and digits[0] in "78":
        return "+7" + digits[1:]
    if len(digits) == 10 and digits[0] == "9":
        return "+7" + digits
    return str(value or "").strip()


def _num(value) -> float | None:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def scrub_args(args: dict) -> dict:
    """Что можно положить в журнал. Секрет заменяется на его длину, не на значение."""
    out: dict = {}
    for key, value in (args or {}).items():
        if key in SECRET_ARGS:
            out[key] = f"<{len(str(value))} симв., не сохраняется>" if value not in ("", None) else ""
        else:
            out[key] = value
    return out


def signature(tool: str, args: dict) -> str:
    """Отпечаток «этот же самый вызов».

    Нужен для одноразового подтверждения: человек подтвердил 100 ₽ Алёне — агент
    должен получить право выполнить именно этот вызов, а не «перевод вообще».
    Секреты в отпечаток не входят: OTP у повторного вызова законно другой, и
    подтверждение не должно из-за этого протухать.
    """
    payload = {k: str(v) for k, v in sorted((args or {}).items()) if k not in SECRET_ARGS}
    canon = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(f"{tool}|{canon}".encode()).hexdigest()[:32]


def extract(tool: str, args: dict, agent: str = "") -> dict:
    """Полный набор фактов о вызове."""
    args = args or {}
    mapping = FACET_MAP.get(tool, {})
    facets: dict = {
        "tool": tool,
        "kind": kind_of(tool),
        "category": category_of(tool),
        "agent": agent or "",
        "amount": None,
        "recipient": "",
        "recipient_name": "",
        "org": "",
        "provider": "",
        "from_account": "",
        "card": "",
        "group": "",
        "text": "",
        "reveal": "",
    }
    for facet, arg_name in mapping.items():
        if arg_name not in args:
            continue
        value = args[arg_name]
        if facet == "amount":
            facets["amount"] = _num(value)
        elif facet == "recipient":
            facets["recipient"] = norm_phone(value) if value else ""
        elif facet in facets:
            facets[facet] = "" if value is None else str(value)
        else:
            facets[facet] = "" if value is None else str(value)

    # `text` — всё, что человек или агент написал словами: назначение перевода,
    # сообщение в чат, поисковый запрос, состав корзины. Один факт вместо пяти,
    # потому что правило «нигде не должно встречаться слово X» иначе пришлось бы
    # писать пять раз и в шестом туле оно бы не сработало.
    if not facets["text"]:
        for key in ("description", "text", "query", "items", "ingredients", "section",
                    "fields", "seats", "body"):
            if args.get(key):
                facets["text"] = str(args[key])
                break

    # `any` — сырой стог сена для правил вида «подстрока где угодно в запросе».
    haystack = [str(v) for v in facets.values() if v not in (None, "")]
    haystack += [f"{k}={v}" for k, v in scrub_args(args).items()]
    facets["any"] = " ".join(haystack)
    return facets
