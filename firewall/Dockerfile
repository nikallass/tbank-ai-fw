# Вебморда и движок правил. Ничего, кроме Python и SQLite: состояние живёт в
# одном файле на volume, так что бэкап политики — это копия файла, а не дамп БД.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TBANK_FW_DB=/data/firewall.db \
    TZ=Europe/Moscow

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Лимиты считаются по КАЛЕНДАРНЫМ суткам в локальной зоне контейнера, поэтому TZ
# выше — не косметика: без неё «сутки» обнулялись бы в 03:00 по Москве. tzdata уже
# есть в python:3.12-slim, ставить нечего.

# Пишет только в /data. Права на volume выставляет compose.
RUN useradd -r -u 10001 firewall && mkdir -p /data && chown firewall /data
USER firewall

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=2).status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
