"""Зона видимости на обратном пути: что агент увидит в ответе тула.

Правила решают, ЧТО агенту можно сделать. Этот модуль решает, что агент увидит,
и это отдельный вопрос: `card_requisites(reveal=True)` может быть законно
разрешён человеку, который сам его попросил, но номер карты всё равно не обязан
попадать в контекст модели, в логи клиента и в историю переписки.

Маскирование делается на стороне фаервола, а не в MCP, ровно по той же причине,
по которой решения принимает фаервол: правило должно быть в одном месте, и
менять его нужно без перезапуска MCP.
"""
from __future__ import annotations

import re

from . import db

# 13–19 цифр, возможно разделённых пробелами или дефисами. Хвост из четырёх цифр
# остаётся: по нему человек узнаёт свою карту, а списать по нему нельзя.
_RE_PAN = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_RE_CVV = re.compile(r"(?i)\b(cvv|cvc|cvv2|код проверки)\b\s*[:=]?\s*\d{3,4}")


def _mask_pan(match: re.Match) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    # Суммы и id заказов сюда не попадают: у PAN не меньше 13 цифр подряд.
    if len(digits) < 13:
        return match.group(0)
    return "•" * (len(digits) - 4) + digits[-4:]


def apply(text: str) -> str:
    if not text:
        return text
    out = text
    if db.get_setting("mask_pan", "1") == "1":
        out = _RE_PAN.sub(_mask_pan, out)
        out = _RE_CVV.sub(lambda m: f"{m.group(1)}: ***", out)
    for rule in db.jload(db.get_setting("mask_rules_json", "[]"), []):
        if not isinstance(rule, dict):
            continue
        pattern = rule.get("pattern") or ""
        replacement = rule.get("replacement", "***")
        if not pattern:
            continue
        try:
            out = re.sub(pattern, replacement, out)
        except re.error:
            # Кривая регулярка не должна отменять остальные маски и тем более
            # ронять ответ тула.
            continue
    return out
