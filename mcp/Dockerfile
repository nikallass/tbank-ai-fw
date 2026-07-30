# Клиент банка: демон входа и (по желанию) сам MCP по HTTP-транспорту.
#
# Один образ на две роли — код и корневые сертификаты у них общие, а разделять
# их значило бы поддерживать две почти одинаковые сборки. Роль выбирается
# командой в docker-compose.yml.
#
# Playwright и chromium НЕ ставятся: они нужны только продуктовому чекауту
# (grocery_checkout), это ~150 МБ, и тащить их в образ, который в 99% случаев
# поднимает форму входа, незачем. Кому нужен чекаут — собирайте с
# `--build-arg WITH_BROWSER=1`.
FROM python:3.12-slim

ARG WITH_BROWSER=0

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Europe/Moscow \
    TBANK_SESSION=/session/session.json \
    # Бандл доверенных корней собирается на лету и должен лежать там, куда
    # процесс может писать: контейнер работает под uid пользователя, а /srv
    # принадлежит root. Без этого падает TLS ко ВСЕМ хостам банка.
    TBANK_CA_BUNDLE=/tmp/tbank-ca-bundle.pem

WORKDIR /srv

COPY pyproject.toml README.md ./
COPY src ./src
COPY ca ./ca
COPY docs ./docs

RUN pip install --no-cache-dir -e . \
    && if [ "$WITH_BROWSER" = "1" ]; then \
         pip install --no-cache-dir playwright && python -m playwright install --with-deps chromium; \
       fi

# Каталог сессии монтируется снаружи. Создаём заранее, чтобы права на точке
# монтирования были предсказуемы, если том пустой.
RUN mkdir -p /session

# Пользователь задаётся в compose (user: "uid:gid") — файл сессии должен быть
# читаем тем, кто запускает MCP, а на Linux это не тот же uid, что в образе.
EXPOSE 8765 8000

CMD ["python", "-m", "src.authd"]
