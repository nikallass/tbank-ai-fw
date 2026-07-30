# Клиент банка: демон входа и (по желанию) сам MCP по HTTP-транспорту.
#
# Один образ на две роли — код и корневые сертификаты у них общие, а разделять
# их значило бы поддерживать две почти одинаковые сборки. Роль выбирается
# командой в docker-compose.yml.
#
# Chromium ставится только там, где он нужен. Нужен он ровно одному тулу —
# grocery_checkout: чекаут продуктов живёт в вебвью на www.tbank.ru, и его JS
# сам заводит CSRF-токены, слоты доставки и веб-сессию. Без браузера этот шаг
# не воспроизвести, остальные покупки (билеты, счета, переводы) — чистое API.
#
# Демон входа браузер не открывает никогда, поэтому его образ собирается с
# WITH_BROWSER=0 и остаётся лёгким; образ MCP — с 1. Разные аргументы сборки =
# разные образы, и это дешевле, чем таскать 400 МБ в контейнер формы логина.
FROM python:3.12-slim

ARG WITH_BROWSER=0

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Europe/Moscow \
    TBANK_SESSION=/session/session.json \
    # Бандл доверенных корней собирается на лету и должен лежать там, куда
    # процесс может писать: контейнер работает под uid пользователя, а /srv
    # принадлежит root. Без этого падает TLS ко ВСЕМ хостам банка.
    TBANK_CA_BUNDLE=/tmp/tbank-ca-bundle.pem \
    # Браузер ставится под root на сборке, а работает контейнер под uid
    # пользователя — в его $HOME (которого нет) playwright искать не должен.
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    HOME=/tmp

WORKDIR /srv

COPY pyproject.toml README.md ./
COPY src ./src
COPY ca ./ca
COPY docs ./docs

RUN pip install --no-cache-dir -e . \
    && if [ "$WITH_BROWSER" = "1" ]; then \
         python -m playwright install --with-deps chromium \
         && chmod -R a+rX "$PLAYWRIGHT_BROWSERS_PATH"; \
       fi

# Каталог сессии монтируется снаружи. Создаём заранее, чтобы права на точке
# монтирования были предсказуемы, если том пустой.
RUN mkdir -p /session

# Пользователь задаётся в compose (user: "uid:gid") — файл сессии должен быть
# читаем тем, кто запускает MCP, а на Linux это не тот же uid, что в образе.
EXPOSE 8765 8000

CMD ["python", "-m", "src.authd"]
