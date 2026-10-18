# Подтверждение проверок

## Локально: 18 октября 2026

- Python 3.14, macOS.
- pytest: 61 тест прошёл, покрытие приложения 97%.
- Gunicorn + curl: smoke test прошёл (`401 → 401 → 200 → 201 → 200`).
- Bandit: 0 находок, 0 ошибок сканера.
- Snyk локально не запускался; результат проверки в GitHub Actions приведён ниже.

Полные локальные отчёты сохраняются в `reports/` и исключены из Git.

## GitHub Actions

[Успешный запуск № 6](https://github.com/p11menova/cybersec/actions/runs/39157669514), 18 октября 2026.

- **API tests** — успешно, включая HTTP smoke test.
- **SAST — Bandit** — успешно.
- **SCA — Snyk** — успешно; блокирующих уязвимостей High/Critical не обнаружено.

Общий статус — **Success**. Все три задания завершились успешно; длительность запуска — 33 секунды.

Настоящий скриншот страницы GitHub Actions:

![GitHub Actions: тесты, Bandit и Snyk прошли](screenshots/actions-summary.jpg)

[Запуски workflow](https://github.com/p11menova/cybersec/actions/workflows/ci.yml).

Артефакты: `sast-bandit`, `sca-snyk`, `test-reports`.
Они содержат полные отчёты сканеров и результаты тестов.
