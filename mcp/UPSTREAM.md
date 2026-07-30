# Происхождение этого каталога

Это вендоренная копия **[tbank-mcp](https://github.com/icyberdeveloper/tbank-mcp)**
авторства [icyberdeveloper](https://github.com/icyberdeveloper), MIT.
Оригинальная лицензия и копирайт сохранены в `LICENSE` рядом.

| | |
|---|---|
| Апстрим | `https://github.com/icyberdeveloper/tbank-mcp.git` |
| Базовый коммит | `3d1496af3d4c56b0719930fdccc87d2de2a01aa6` |
| Дата коммита | 2026-07-26T22:01:02+00:00 |

## Что изменено относительно апстрима

Правки намеренно локализованы, чтобы обновление из апстрима оставалось посильным:

| Файл | Что |
|---|---|
| `src/guard.py` | **новый** — весь слой фаервола: authorize → вызов → result |
| `src/authd.py` | **новый** — демон входа для веб-формы, сессия остаётся на хосте |
| `bin/tbank-authd` | **новый** — запуск демона |
| `tests/test_firewall_guard.py` | **новый** — врезка против заглушки фаервола |
| `tests/test_authd.py` | **новый** — шаги входа и границы доверия |
| `tests/test_device_and_outcome.py` | **новый** — одно устройство на сессию, 4xx ≠ неизвестность |
| `src/server.py` | врезка в `_traced_tool`, три тула `firewall_*`, `_bank_refused`, статус операций в `list_operations` |
| `src/client.py` | `CAPTURED_DEVICE` как единственный источник фактов об устройстве; `_unwrap` сохраняет тело не-JSON ответа |
| `pyproject.toml` | пин `mcp<2` — SDK 2.0 переименовал `fastmcp`, чистая установка ломалась на импорте |
| `README.md`, `skills/tbank/SKILL.md` | описание врезки для человека и для агента |

Полный диф на момент вендоринга — `../docs/upstream-diff.patch`.

## Как обновляться из апстрима

```bash
cd mcp
git init && git remote add upstream https://github.com/icyberdeveloper/tbank-mcp.git
git fetch upstream && git diff HEAD upstream/main -- src/ tests/
```

Конфликты будут только в файлах из таблицы выше.
