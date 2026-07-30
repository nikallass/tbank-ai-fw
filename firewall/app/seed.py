"""Стартовая политика.

Заводится один раз, при первом запуске пустой базы. Смысл не в том, чтобы угадать
чужие правила, а в том, чтобы на первом же экране было видно, ЧТО вообще можно
описать: чёрный список, белый список, регулярка по тексту, потолок одной
операции, суточный потолок, ручное подтверждение.

Дефолт осознанно строгий на деньгах и свободный на чтении: агент, который не может
посмотреть баланс, бесполезен, а агент, который молча переводит деньги, — опасен.
Правило про белый список получателей идёт ВЫКЛЮЧЕННЫМ: список пуст, и включённое
оно запретило бы вообще все переводы, чему пользователь бы не обрадовался.
"""
from __future__ import annotations

import json
import time

from . import db

LISTS = [
    {
        "name": "Доверенные получатели",
        "kind": "recipients",
        "note": "Кому агент может переводить без вопросов. Телефоны нормализуются "
                "к виду +7XXXXXXXXXX, так что формат ввода значения не имеет.",
        "entries": [],
    },
    {
        "name": "Запрещённые получатели",
        "kind": "recipients",
        "note": "Жёсткий запрет, срабатывает раньше всех остальных правил.",
        "entries": [],
    },
    {
        "name": "Стоп-слова",
        "kind": "text",
        "note": "Ищутся в назначении перевода, сообщении, поисковом запросе и "
                "составе корзины.",
        "entries": [
            {"match": "regex", "value": "(?i)крипт|usdt|bitcoin|btc",
             "note": "криптовалюта"},
            {"match": "regex", "value": "(?i)казино|casino|ставк|букмекер",
             "note": "азартные игры"},
            {"match": "substring", "value": "срочно переведи",
             "note": "типовая фраза из мошеннической схемы"},
        ],
    },
    {
        "name": "Разрешённые магазины",
        "kind": "orgs",
        "note": "app_id магазинов из grocery_stores(). Пусто = ограничения нет.",
        "entries": [],
    },
]

RULES = [
    {
        "priority": 10, "name": "Стоп-слова в запросе", "action": "deny", "enabled": 1,
        "reason": "в запросе встретилось стоп-слово",
        "match": {"conditions": [{"field": "any", "op": "in_list", "value": "Стоп-слова"}]},
    },
    {
        "priority": 15, "name": "Чёрный список получателей", "action": "deny", "enabled": 1,
        "reason": "получатель в чёрном списке",
        "match": {"conditions": [
            {"field": "recipient", "op": "in_list", "value": "Запрещённые получатели"}]},
    },
    {
        "priority": 20, "name": "Только доверенные получатели (белый список)",
        "action": "deny", "enabled": 0,
        "reason": "получателя нет в белом списке",
        "match": {"kinds": ["money"], "conditions_mode": "all", "conditions": [
            {"field": "recipient", "op": "not_empty", "value": ""},
            {"field": "recipient", "op": "not_in_list", "value": "Доверенные получатели"}]},
    },
    {
        "priority": 30, "name": "Полные реквизиты карты и CVV", "action": "hitl", "enabled": 1,
        "reason": "агент просит полный номер карты и CVV — это доступ к оплате",
        "match": {"tools": ["card_requisites"], "conditions": [
            {"field": "reveal", "op": "in", "value": "True,true,1"}]},
    },
    {
        "priority": 40, "name": "Оплата продуктов без подтверждённой суммы",
        "action": "deny", "enabled": 1,
        "reason": "чекаут без expected_sum: сумма корзины не видна ни человеку, ни фаерволу",
        "match": {"tools": ["grocery_checkout"], "conditions": [
            {"field": "amount", "op": "is_empty", "value": ""}]},
    },
    {
        "priority": 50, "name": "Мелкие переводы доверенным — без вопросов",
        "action": "allow", "enabled": 1,
        "reason": "доверенный получатель, сумма до 1000 ₽",
        "match": {"tools": ["transfer"], "conditions_mode": "all", "conditions": [
            {"field": "amount", "op": "lte", "value": 1000},
            {"field": "recipient", "op": "in_list", "value": "Доверенные получатели"}]},
    },
    {
        # Готовый шаблон под самый частый запрос: «мелочь пусть тратит сам, но
        # с нормой». ВЫКЛЮЧЕН по умолчанию — фаервол, который из коробки молча
        # проводит три платежа в сутки, это сюрприз, а не защита. Включается
        # галочкой, суммы и категории правятся там же.
        "priority": 55, "name": "Мелкие траты — норма без подтверждения",
        "action": "allow", "enabled": 0,
        "reason": "мелкая трата в пределах суточной нормы",
        "match": {"kinds": ["money"], "conditions": [
            {"field": "amount", "op": "lte", "value": 3000}]},
        "quota": {"window": "day", "max_count": 3, "max_amount": 6000,
                  "on_exceed": "hitl"},
    },
    {
        "priority": 60, "name": "Любые деньги — подтверждение человеком",
        "action": "hitl", "enabled": 1,
        "reason": "операция списывает деньги",
        "match": {"kinds": ["money"]},
    },
    {
        "priority": 70, "name": "Отправка сообщения живому человеку",
        "action": "hitl", "enabled": 1,
        "reason": "сообщение прочитает человек и отозвать его нельзя",
        "match": {"tools": ["messenger_send"]},
    },
    {
        "priority": 80, "name": "Чтение — разрешено", "action": "allow", "enabled": 1,
        "reason": "чтение данных",
        "match": {"kinds": ["read"]},
    },
    {
        "priority": 90, "name": "Корзина, бронь, черновики — разрешено",
        "action": "allow", "enabled": 1,
        "reason": "изменение, которое не стоит денег",
        "match": {"kinds": ["write"]},
    },
]

LIMITS = [
    {"name": "Одна операция — не больше 15 000 ₽", "window": "tx",
     "max_amount": 15000, "max_count": None, "on_exceed": "deny",
     "match": {"kinds": ["money"]}},
    {"name": "Не больше 30 000 ₽ в сутки", "window": "day",
     "max_amount": 30000, "max_count": None, "on_exceed": "deny",
     "match": {"kinds": ["money"]}},
    {"name": "Не больше 10 платежей в сутки", "window": "day",
     "max_amount": None, "max_count": 10, "on_exceed": "hitl",
     "match": {"kinds": ["money"]}},
    {"name": "Переводы — не больше 50 000 ₽ в месяц", "window": "month",
     "max_amount": 50000, "max_count": None, "on_exceed": "deny",
     "match": {"categories": ["transfer"]}},
]


def seed_if_empty() -> bool:
    """True, если политику действительно завели (база была пустой)."""
    if db.one("SELECT id FROM rules LIMIT 1") is not None:
        return False
    now = time.time()
    for item in LISTS:
        db.run("INSERT INTO lists(name, kind, entries_json, note, created_at) VALUES (?,?,?,?,?)",
               (item["name"], item["kind"], json.dumps(item["entries"], ensure_ascii=False),
                item["note"], now))
    for item in RULES:
        q = item.get("quota") or {}
        db.run(
            "INSERT INTO rules(name, enabled, priority, action, match_json, hitl_mode, "
            "skip_limits, reason, created_at, updated_at, quota_window, quota_max_count, "
            "quota_max_amount, quota_on_exceed) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (item["name"], item["enabled"], item["priority"], item["action"],
             json.dumps(item["match"], ensure_ascii=False), "", 0, item["reason"], now, now,
             q.get("window", ""), q.get("max_count"), q.get("max_amount"),
             q.get("on_exceed", "hitl")))
    for item in LIMITS:
        db.run(
            "INSERT INTO limits(name, enabled, match_json, window, max_amount, max_count, "
            "on_exceed, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (item["name"], 1, json.dumps(item["match"], ensure_ascii=False), item["window"],
             item["max_amount"], item["max_count"], item["on_exceed"], now))
    return True
