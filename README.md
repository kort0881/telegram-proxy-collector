# 🛡️ Telegram Proxy Collector: Anti‑Censorship Edition

[![oosmetrics — Топ‑5 в категории Crypto](https://api.oosmetrics.com/api/v1/badge/achievement/21322b63-7982-4e81-99f7-ada7354f9c21.svg)](https://oosmetrics.com/repo/kort0881/telegram-proxy-collector)

**Умный комбайн** для сбора, анализа и отбора **MTProto** и **SOCKS5** прокси.  
В отличие от обычных парсеров, этот скрипт **глубоко анализирует** `Secret` каждого MTProto‑прокси, извлекает **домен‑маску** (Yandex, VK, Mail.ru, Gosuslugi, Google, Amazon, Microsoft и др.) и проверяет **устойчивость к активному DPI** (Probe Resistance).  
Это особенно важно в условиях жёстких блокировок, где **маскировка под легитимный HTTPS** или использование SOCKS5 может быть разницей между работой и полной недоступностью.

👉 [GitHub — Telegram Proxy Collector](https://github.com/kort0881/telegram-proxy-collector)

---

## 📌 Что нового в версии 3.1

- **✅ Фильтрация по пингу** — прокси с откликом >3 секунд автоматически отсеиваются (параметр `--max-ping`).
- **🔐 Поддержка URL‑safe Base64** — корректно декодируются секреты с символами `-` и `_`.
- **🇷🇺 Для RU‑прокси теперь обязательно** наличие флага `probe_resistant` — это гарантирует, что прокси маскируется под легитимный HTTPS и устойчив к DPI-зондированию.
- **⏱️ Увеличен таймаут** до 14 секунд (по умолчанию в GitHub Actions) — даёт шанс медленным, но живым прокси ответить.
- **⚙️ Снижена параллельность** до 20 воркеров — предотвращает `FloodWait` от Telegram.
- **📡 Добавлен сбор из Telegram‑каналов** (например, `@ProxyMTProto`) через параметр `--channel`.
- **🧹 Улучшен парсинг** — теперь извлекаются прокси из большего числа форматов (YAML, JSON, специальные списки).
- **📊 Более строгая сортировка** — сначала `probe_resistant`, затем обычные MTProto, затем SOCKS5, внутри каждой группы по возрастанию пинга.

---

## 🛠️ Community Tools: утилиты от пользователей

| Инструмент | Описание | Автор |
| --- | --- | --- |
| [Parser‑telegram‑proxies](https://github.com/ComradeBingo/Parser-telegram-proxies-list/) | Удобная Windows‑утилита для парсинга и проверки MTProto‑прокси с **отображением пинга в реальном времени**. Обновлённая версия исправляет периодические блокировки запросов к TXT‑файлам на GitHub за счёт использования HTTP‑запросов вместо прямого чтения. | [ComradeBingo](https://github.com/ComradeBingo) |
| [Proxy‑Telegram‑Android](https://github.com/ComradeBingo/Proxy-Telegram-Android) | Приложение для Android, которое **парсит прокси‑списки**, проверяет их доступность и показывает пинг серверов. | [ComradeBingo](https://github.com/ComradeBingo) |
| [Proxy‑telegram‑windows](https://github.com/ComradeBingo/Proxy-telegram-windows) | Парсер прокси‑серверов для Telegram на Windows. Обновлён до версии **1.2**: переработан GUI, добавлено меню «Справка», улучшена стабильность и удобство использования. | [ComradeBingo](https://github.com/ComradeBingo) |

---

## 🔥 **Актуальные списки** (обновляются автоматически **каждый час**)

Скрипт **ежечасно** запускается через [GitHub Actions](https://github.com/kort0881/telegram-proxy-collector/actions), **собирает** свежие прокси из открытых источников, **фильтрует**, **проверяет** и **обновляет** списки.  
GitHub Actions **сохраняет результаты** в папку `verified/`, а затем **копирует** их в корень репозитория — поэтому **ссылки ниже всегда ведут на свежие списки**.

📦 **Прямые ссылки** для вставки в Telegram или свои программы:

| Регион / Тип | Список | Примечание |
| --- | --- | --- |
| 🇷🇺 RU‑сегмент (MTProto) | [proxy_ru.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_ru.txt) | Маскировка под **Yandex, VK, Mail.ru, Gosuslugi, Sber, Mos.ru** и др. Нацелен на **лучшую стабильность в РФ и Иране**. |
| 🇪🇺 EU / Global (MTProto) | [proxy_eu.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_eu.txt) | Маскировка под **Google, Amazon, Microsoft, Cloudflare** и другие международные сервисы. Высокая скорость и стабильность, особенно вне РФ. |
| 🌍 Все MTProto прокси | [proxy_all.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_all.txt) | Полный микс всех проверенных MTProto‑серверов (RU + EU). |
| 🔒 **SOCKS5 прокси** | [socks5.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/socks5.txt) | Прокси протокола SOCKS5 (без маскировки, но часто сложнее блокируются). |

---

## 📱 **Использование с телефона**

Если ты открыл репозиторий **с телефона** и не хочешь копировать прокси вручную:

1. Открой страницу:  
   [https://kort0881.github.io/telegram-proxy-collector/](https://kort0881.github.io/telegram-proxy-collector/)  
   (этот же файл `index.html` находится в корне репозитория)
2. На странице есть **три вкладки**:  
   - **MTProto RU** – прокси с маскировкой под российские сайты,  
   - **MTProto EU** – международная маскировка,  
   - **SOCKS5** – прокси без маскировки, но часто работающие там, где MTProto блокируется.
3. Нажми на любую кнопку – Telegram сам предложит подключиться.

Также доступна специальная мобильная версия:  
👉 [mobile.html](https://kort0881.github.io/telegram-proxy-collector/mobile.html) — она оптимизирована для небольших экранов и имеет упрощённый интерфейс.

---

## 🚀 **Как это работает?**

Скрипт **запускается каждый час** через [GitHub Actions](https://github.com/kort0881/telegram-proxy-collector/actions) и последовательно проходит **пять главных этапов**:

### 1. Сбор (Harvesting)

- Скачивает «сырые» прокси из **двух категорий источников**:
  - **MTProto** (основные репозитории, API, TXT‑файлы)
  - **SOCKS5** (специализированные списки)
- Использует **агрессивный Regex‑парсинг** для извлечения ссылок из любого формата:
  - `tg://proxy?server=...&port=...&secret=...`
  - `tg://socks?server=...&port=...`
  - `t.me/proxy?...`
  - `host:port:secret`
  - `socks5://[user:pass@]host:port`
  - JSON‑объекты.

### 2. Декодирование (Deep Analysis)

- Расшифровывает **Fake‑TLS‑секреты** MTProto (начинаются на `ee...`).
- Извлекает **домен**, под который идёт маскировка трафика (например `yandex.ru`, `vk.com`, `google.com` и т.д.).
- На основе домена **помечает** MTProto прокси как `ru` или `eu` (по набору ключевых слов в URL).

### 3. Фильтрация (Smart Filter)

- ❌ **Blacklist:** прокси, маскирующиеся под **заведомо заблокированные ресурсы** (Instagram, Facebook, Twitter, BBC, Meduza, LinkedIn, Tor и др.), **отбрасываются**.
- ✅ **RU‑маркер:** прокси, содержащие в домене `yandex`, `vk.com`, `mail.ru`, `ok.ru`, `sber`, `tinkoff`, `gosuslugi`, `ozon`, `wildberries`, `avito`, `kinopoisk` и др., помечаются как `ru`.
- ✅ **EU‑маркер:** остальные MTProto прокси считаются `eu`.

### 4. Проверка (Checking) — **включая Probe Resistance**

- Проверяет каждый прокси через **TCP‑сокет** (быстрый режим) или через **Telethon** (полная проверка с подключением к Telegram API, если переданы `API_ID` и `API_HASH`).
- Для MTProto прокси с доменом (секрет `ee...`) запускается **Probe Resistance Test** – скрипт отправляет обычный HTTPS‑запрос `GET /` с заголовком `Host: <домен>` через прокси. Если прокси отвечает настоящей HTML‑страницей, он считается **устойчивым к активному зондированию DPI** и получает флаг `probe_resistant: true`.
- SOCKS5 прокси проверяются только на возможность подключения к Telegram API (без маскировки).
- Результат сохраняется в `verified/proxy_all_verified.json` с полями `probe_resistant` и `type`.

### 5. Сборка итоговых списков

- Все прокси **сортируются по приоритету**:
  1. MTProto с `probe_resistant: true` (самые живучие)
  2. Обычные MTProto
  3. SOCKS5
- Внутри каждой группы – по возрастанию пинга.
- MTProto прокси разделяются на **RU** и **EU**.
- SOCKS5 прокси выносятся в отдельный файл `socks5.txt`.
- Формируются файлы:
  - `proxy_ru.txt`, `proxy_eu.txt`, `proxy_all.txt` (MTProto ссылки)
  - `socks5.txt` (SOCKS5 ссылки)
  - `verified/` – подробные копии с комментариями и JSON.

---

## 📁 **Итоговые файлы**

После каждого запуска вы получите:

- **Корень репозитория** (удобно для прямых ссылок):
  - `proxy_ru.txt`, `proxy_eu.txt`, `proxy_all.txt` — MTProto `tg://proxy?...`
  - `socks5.txt` — SOCKS5 `tg://socks?...`
- **Папка `verified/`** (подробные версии):
  - `proxy_ru_verified.txt`, `proxy_eu_verified.txt`, `proxy_all_verified.txt` — с заголовками и статистикой.
  - `socks5_proxies.txt` — SOCKS5 с комментариями.
  - `proxy_all_verified.json` — полный JSON с полями: `type`, `host`, `port`, `ping`, `region`, `domain`, `method`, `probe_resistant`.
  - `proxy_stats_verified.json` — статистика по запуску (количество сырых/рабочих, время выполнения, лучший ping).

---

## 🔗 **Мои проекты**

| Проект | Описание | Ссылка |
| --- | --- | --- |
| [VPN KEY VLESS](https://t.me/vlesstrojan) | Основной канал с конфигами, инструкциями и новостями по VLESS‑конфигам и прокси‑сети. | [Telegram](https://t.me/vlesstrojan) |
| [KiberSos New](https://t.me/kibersosnew) | Резервный канал для связи, обновлений и техподдержки. | [Telegram](https://t.me/kibersosnew) |
| [VlessBots](https://t.me/vlessbots_bot) | Бот для **автоматической выдачи ключей** и прокси‑ссылок по запросу. | [Bot](https://t.me/vlessbots_bot) |
| [Internet Access](https://kort0881.github.io/internet-access-site/) | Сайт проекта с подробной документацией, FAQ и примерами использования. | [Website](https://kort0881.github.io/internet-access-site/) |
| [VPN Key Repo](https://github.com/kort0881/vpn-key-vless) | Репозиторий скриптов, конфигураций и утилит для работы с VLESS‑сервисами и прокси‑сетями. | [GitHub](https://github.com/kort0881/vpn-key-vless) |

---

## 🛠️ **Локальный запуск (для разработчиков)**

Если хочешь запустить сборщик **на своём ПК**, а не только на GitHub Actions:

```bash
# 1. Клонировать репозиторий
git clone https://github.com/kort0881/telegram-proxy-collector.git
cd telegram-proxy-collector

# 2. Установить зависимости
pip install -r requirements.txt

# 3. Запустить базовую проверку (только TCP‑пинг)
python main.py

# 4. Запустить полную проверку (с Telethon, Probe Resistance и SOCKS5)
python main.py --api-id YOUR_API_ID --api-hash YOUR_API_HASH --top 200 --timeout 14 --workers 20 --channel @ProxyMTProto --channel-limit 150 --max-ping 3.0 --output-dir verified

# 5. Помощь по аргументам
python main.py --help

Для полной проверки (Telethon) необходимы API_ID и API_HASH. Их можно получить на my.telegram.org.

⚠️ Дисклеймер и безопасность
Этот репозиторий не гарантирует анонимность, невозможность слежки или защищённость от компрометации.
Все прокси‑серверы предоставляются на условиях «как есть», и их качество зависит от внешних источников.


## 📊 AI-аналитика (автоматическая)

<!-- AI_ANALYTICS_START -->
*Отчёт сгенерирован 2026-07-19 13:45 UTC*

### Отчёт о прокси-серверах
Текущий список прокси-серверов состоит из 200 записей, все из которых имеют хорошее качество с пингом менее 1,5 секунды. Распределение по регионам: США — 10, Европа — 154, Россия — 36.

### Рекомендации
Рекомендуется использовать прокси-сервера с типом `mtproto` в регионах Европы и России, так как они демонстрируют высокий уровень качества и стабильности. Все прокси-сервера в списке имеют хорошие показатели, поэтому можно выбирать любой из них в зависимости от нужного региона.

### Аномалии
Отсутствуют аномалии в списке прокси-серверов, все из них имеют хорошее качество и низкий пинг.

### Дата отчёта
Отчёт сформирован: 19 июля 2026 г., 00:00.
<!-- AI_ANALYTICS_END -->