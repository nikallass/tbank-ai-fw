"""Каталог тулов T-Bank MCP: что это, чем рискует, из каких аргументов достаются факты.

ЗАЧЕМ ОТДЕЛЬНЫЙ КАТАЛОГ, А НЕ ДОВЕРИЕ ТОМУ, ЧТО ПРИСЛАЛ MCP.
Решение о деньгах нельзя принимать по метаданным, которые прислала сторона,
чьё поведение мы и ограничиваем. MCP присылает `kind`, но фаервол сверяет его
со своей таблицей и при расхождении берёт СВОЙ (более строгий) вариант — иначе
достаточно было бы прислать kind="read" на transfer, чтобы обойти все правила
про деньги. Тул, которого в таблице нет, считается MONEY: неизвестное — опасно.

FACET_MAP — единственное место, где «аргумент тула» превращается в «факт, по
которому пишут правило». Пользователь в вебморде оперирует словами «сумма»,
«получатель», «счёт списания», а не `to_account`/`expected_sum`/`account_id`,
и раскладка между ними живёт здесь, а не размазана по движку правил.
"""
from __future__ import annotations

READ, WRITE, MONEY = "read", "write", "money"

# (заголовок, kind, категория)
TOOLS: dict[str, tuple[str, str, str]] = {
    # ── сессия ────────────────────────────────────────────────────────────
    "login": ("Вход по телефону", WRITE, "session"),
    "confirm_otp": ("Подтверждение кода из SMS", WRITE, "session"),
    "confirm_password": ("Подтверждение пароля", WRITE, "session"),
    "confirm_pin": ("Подтверждение PIN", WRITE, "session"),
    "refresh_session": ("Обновление сессии", WRITE, "session"),
    "session_status": ("Статус сессии", READ, "session"),
    "keepalive": ("Продление сессии", READ, "session"),
    # ── счета и операции ──────────────────────────────────────────────────
    "list_accounts": ("Счета", READ, "accounts"),
    "list_operations": ("Операции по счёту", READ, "operations"),
    "spending_categories": ("Траты по категориям", READ, "operations"),
    "operations_histogram": ("График трат", READ, "operations"),
    "get_data": ("Банковские данные по разделам", READ, "accounts"),
    "account_requisites": ("Реквизиты счёта", READ, "accounts"),
    # ── карты и документы ─────────────────────────────────────────────────
    "list_cards": ("Карты", READ, "cards"),
    "card_limits": ("Лимиты карты", READ, "cards"),
    "card_requisites": ("Реквизиты карты", READ, "cards"),
    "card_operations": ("Операции по карте", READ, "operations"),
    "documents": ("Документы клиента", READ, "documents"),
    "bank_documents": ("Справки банка", READ, "documents"),
    "insurance_policies": ("Страховые полисы", READ, "documents"),
    "payment_receipt": ("Скачивание чека в файл", WRITE, "documents"),
    # ── заказы ────────────────────────────────────────────────────────────
    "orders": ("Заказы", READ, "orders"),
    "order_details": ("Детали заказа", READ, "orders"),
    "travel_order_details": ("Детали поездки", READ, "orders"),
    # ── продукты ──────────────────────────────────────────────────────────
    "grocery_stores": ("Магазины и доставка", READ, "grocery"),
    "grocery_search": ("Поиск товара", READ, "grocery"),
    "grocery_rank": ("Товары с сортировкой", READ, "grocery"),
    "grocery_good_info": ("Карточка товара и КБЖУ", READ, "grocery"),
    "grocery_plan_order": ("Планирование заказа", READ, "grocery"),
    "grocery_cart": ("Содержимое корзины", READ, "grocery"),
    "grocery_attempts": ("Попытки оформления", READ, "grocery"),
    "grocery_order_status": ("Статус заказа", READ, "grocery"),
    "grocery_add_to_cart": ("Добавление в корзину", WRITE, "grocery"),
    "grocery_set_cart": ("Перезапись корзины", WRITE, "grocery"),
    "grocery_checkout": ("Оформление и оплата заказа", MONEY, "grocery"),
    "grocery_order_cancel": ("Отмена продуктового заказа", WRITE, "grocery"),
    # ── билеты ────────────────────────────────────────────────────────────
    "cinema_search": ("Поиск фильма", READ, "tickets"),
    "cinema_schedule": ("Расписание сеансов", READ, "tickets"),
    "cinema_seats": ("Свободные места", READ, "tickets"),
    "concert_schedule": ("Показы концерта", READ, "tickets"),
    "concert_hall": ("Секторы концертной площадки", READ, "tickets"),
    "cinema_book": ("Бронирование мест", WRITE, "tickets"),
    "ticket_pay": ("Оплата брони", MONEY, "tickets"),
    "ticket_cancel": ("Отмена заказа", WRITE, "tickets"),
    # ── поиск ─────────────────────────────────────────────────────────────
    "search_app": ("Поиск по приложению", READ, "search"),
    # ── мессенджер ────────────────────────────────────────────────────────
    "messenger_conversations": ("Чаты", READ, "messenger"),
    "messenger_messages": ("История чата", READ, "messenger"),
    "messenger_unread": ("Непрочитанные", READ, "messenger"),
    "messenger_send": ("Отправка сообщения", WRITE, "messenger"),
    # ── деньги ────────────────────────────────────────────────────────────
    "transfer_sbp_resolve": ("Получатель СБП по телефону", READ, "transfer"),
    "payment_commission": ("Предпросмотр комиссии", READ, "bills"),
    "payment_providers": ("Каталог платёжных провайдеров", READ, "bills"),
    "pay_bill": ("Оплата счёта", MONEY, "bills"),
    "transfer": ("Перевод денег", MONEY, "transfer"),
    # ── инвестиции ────────────────────────────────────────────────────────
    "invest_accounts": ("Инвест-счета", READ, "invest"),
    "invest_portfolio": ("Статистика портфеля", READ, "invest"),
    "invest_operations": ("Брокерские операции", READ, "invest"),
    "invest_securities": ("Бумаги в портфеле", READ, "invest"),
    # ── служебные ─────────────────────────────────────────────────────────
    "flows": ("Порядок вызовов по теме", READ, "utility"),
    "diagnostics": ("События последних оплат", READ, "utility"),
    "debug_report": ("Как использовали этот MCP", READ, "utility"),
}

CATEGORIES: dict[str, str] = {
    "session": "Сессия и вход",
    "accounts": "Счета",
    "operations": "Операции и выписки",
    "cards": "Карты",
    "documents": "Документы",
    "orders": "Заказы",
    "grocery": "Продукты",
    "tickets": "Билеты",
    "search": "Поиск",
    "messenger": "Мессенджер",
    "transfer": "Переводы",
    "bills": "Счета и платежи",
    "invest": "Инвестиции",
    "utility": "Служебное",
}

KIND_TITLES = {READ: "чтение", WRITE: "запись", MONEY: "деньги"}

# Раскладка аргументов тула в факты, по которым пишутся правила.
# Ключ — имя факта в правиле, значение — имя аргумента тула.
FACET_MAP: dict[str, dict[str, str]] = {
    "transfer": {
        "amount": "amount", "recipient": "to_account", "recipient_name": "masked_fio",
        "from_account": "from_account", "provider": "provider", "text": "description",
        # Маршрут получателя в СБП. Их нельзя ни угадать, ни вывести из номера —
        # банк отдаёт их в transfer_sbp_resolve. Здесь они факты правил, потому
        # что по ним же проверяется, что агент их не сочинил (policy.check_requisites).
        "bank_member_id": "bank_member_id", "pointer_link_id": "pointer_link_id",
    },
    "pay_bill": {
        "amount": "amount", "org": "provider_id", "from_account": "from_account",
        "text": "fields", "group": "group",
    },
    # expected_sum — сумма, которую подтвердил пользователь. Она же единственный
    # аргумент чекаута, в котором вообще видны деньги: состав корзины лежит на
    # стороне банка. Правило «продукты дороже N» без неё не построить, поэтому
    # сид-политика отдельно требует expected_sum > 0.
    "grocery_checkout": {
        "amount": "expected_sum", "org": "app_id", "from_account": "account_id",
        "point": "point_id",
    },
    "ticket_pay": {
        "amount": "amount", "org": "order_id", "from_account": "account_id",
    },
    "cinema_book": {"org": "object_id", "text": "seats", "event": "event_id"},
    "ticket_cancel": {"org": "order_id"},
    "messenger_send": {"text": "text", "org": "conversation_id"},
    "messenger_messages": {"org": "conversation_id"},
    "transfer_sbp_resolve": {"recipient": "phone"},
    "payment_commission": {"text": "body"},
    "payment_providers": {"org": "provider_id", "text": "query", "group": "group"},
    "card_requisites": {"card": "ucid", "reveal": "reveal"},
    "card_limits": {"card": "ucid"},
    "card_operations": {"card": "card_id"},
    "list_operations": {"from_account": "account_id"},
    "spending_categories": {"from_account": "account_id"},
    "operations_histogram": {"from_account": "account_id"},
    "account_requisites": {"from_account": "account_id"},
    "grocery_search": {"org": "app_id", "text": "query"},
    "grocery_add_to_cart": {"org": "app_id", "text": "items"},
    "grocery_set_cart": {"org": "app_id", "text": "items"},
    "grocery_cart": {"org": "app_id"},
    "grocery_plan_order": {"org": "app_id", "text": "ingredients"},
    "grocery_order_status": {"org": "order_id"},
    "grocery_order_cancel": {"org": "order_id"},
    "order_details": {"org": "order_id"},
    "travel_order_details": {"org": "order_id"},
    "payment_receipt": {"org": "payment_id", "text": "save_to"},
    "get_data": {"text": "section"},
    "search_app": {"text": "query"},
    "login": {"recipient": "phone"},
    "invest_portfolio": {"from_account": "broker_account_id"},
    "invest_operations": {"from_account": "broker_account_id"},
    "invest_securities": {"from_account": "broker_account_id"},
}

# Аргументы, которые нельзя писать в журнал даже в зашифрованном виде.
# Их наличие фиксируется, значение — никогда.
SECRET_ARGS = {"password", "pin", "otp", "code", "nfs_payment_token"}

# Поля, доступные в условиях правил. Порядок = порядок в выпадающем списке UI.
FIELDS: list[tuple[str, str]] = [
    ("tool", "Тул"),
    ("kind", "Тип (чтение/запись/деньги)"),
    ("category", "Категория"),
    ("amount", "Сумма, ₽"),
    ("recipient", "Получатель (телефон/счёт)"),
    ("recipient_name", "Имя получателя"),
    ("org", "Организация / провайдер / заказ"),
    ("provider", "Способ перевода"),
    ("bank_member_id", "Банк получателя в СБП"),
    ("pointer_link_id", "Связка получателя в СБП"),
    ("from_account", "Счёт списания"),
    ("card", "Карта"),
    ("group", "Группа платежа"),
    ("text", "Свободный текст (сообщение, назначение, запрос)"),
    ("reveal", "Флаг раскрытия полных данных"),
    ("agent", "Агент"),
    ("any", "Любое поле (поиск по всему запросу)"),
]

OPS: list[tuple[str, str]] = [
    ("eq", "равно"),
    ("ne", "не равно"),
    ("gt", "больше"),
    ("gte", "больше или равно"),
    ("lt", "меньше"),
    ("lte", "меньше или равно"),
    ("contains", "содержит подстроку"),
    ("not_contains", "не содержит подстроку"),
    ("starts_with", "начинается с"),
    ("ends_with", "заканчивается на"),
    ("regex", "совпадает с регуляркой"),
    ("not_regex", "не совпадает с регуляркой"),
    ("in", "входит в перечень (через запятую)"),
    ("not_in", "не входит в перечень (через запятую)"),
    ("in_list", "входит в список"),
    ("not_in_list", "не входит в список"),
    ("is_empty", "пусто"),
    ("not_empty", "не пусто"),
]


def kind_of(tool: str) -> str:
    """Тип тула по НАШЕЙ таблице. Незнакомый тул — MONEY, а не READ."""
    row = TOOLS.get(tool)
    return row[1] if row else MONEY


def category_of(tool: str) -> str:
    row = TOOLS.get(tool)
    return row[2] if row else "unknown"


def title_of(tool: str) -> str:
    row = TOOLS.get(tool)
    return row[0] if row else tool
