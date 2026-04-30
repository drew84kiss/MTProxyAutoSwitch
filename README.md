<img width="433" height="741" alt="Снимок экрана 2026-05-01 035203" src="https://github.com/user-attachments/assets/8d4cc4b9-7f42-4fe6-96ab-33f1f0a347c0" />
<img width="438" height="745" alt="Снимок экрана 2026-05-01 035157" src="https://github.com/user-attachments/assets/d223f0cf-157a-4ac1-a401-78adb398f642" />

# MTProxy AutoSwitch

`MTProxy AutoSwitch` поднимает локальный MTProto frontend на `127.0.0.1:1443`, собирает прокси из веб-источников и Telegram, проверяет их и автоматически переключает upstream на лучший доступный вариант.

Проект является форком клиента Flowseal:

`https://github.com/Flowseal/tg-ws-proxy`

В оригинальном проекте основной сценарий работы — локальный proxy frontend. В этом форке добавлены:

- парсинг веб- и Telegram-источников
- дедупликация и фильтрация списков
- фоновая проверка доступности и стабильности
- автоподбор лучшего upstream MTProto proxy
- экспорт рабочих списков
- автообновление приложения

## Что умеет приложение

- поднимать локальный MTProto proxy для Telegram на `127.0.0.1:1443`
- автоматически выбирать лучший upstream MTProto proxy
- собирать MTProto и SOCKS5 из веб-источников
- парсить публичные Telegram-каналы через `t.me/s/...`
- парсить Telegram-каналы, группы, сообщения и ветки через Telegram API после входа в аккаунт
- проверять прокси в фоне без полного обновления списка
- делать `deep media check` и строгую media-проверку для сложных сетей
- отправлять список рабочих прокси себе в `Избранное`
- экспортировать результаты в папку `list`
- проверять и устанавливать обновления приложения

## Что лежит в репозитории

- `mtproxy_gui.py` — интерфейс приложения
- `mtproxy_app_backend.py` — runtime, refresh, экспорт, локальный frontend
- `mtproxy_local_proxy.py` — локальный MTProto frontend и pool upstream-прокси
- `mtproxy_collector.py` — веб-парсинг и первичная проверка прокси
- `mtproxy_telegram.py` — Telegram API, авторизация, Telegram-источники, media-check
- `mtproxy_updater.py` — автообновление приложения
- `config.json` — текущий конфиг
- `config.template.json` — шаблон конфига для релизной сборки
- `list/` — экспортированные списки и отчеты

## Как пользоваться

1. Установите и запустите приложение.
2. Нажмите `Обновить`, чтобы собрать и проверить прокси.
3. Нажмите `Пуск`, чтобы поднять локальный proxy frontend.
4. Подключите Telegram к локальному proxy:
   `https://t.me/proxy?server=127.0.0.1&port=1443&secret=<secret>`
5. Если нужно, скопируйте ссылку кнопкой на главном экране.

## Где хранятся данные

Приложение старается отделять установленные файлы от пользовательских данных.

Windows:

- приложение ставится в `%LOCALAPPDATA%\Programs\MTProxy AutoSwitch`
- пользовательские данные хранятся в `%APPDATA%\MTProxyAutoSwitch`

macOS:

- приложение ставится в `/Applications/MTProxyAutoSwitch.app`
- пользовательские данные хранятся в `~/Library/Application Support/MTProxyAutoSwitch`

Это позволяет обновлять приложение через установщик без потери конфигурации, сессии Telegram и сохраненных списков.

## Когда нужен вход в Telegram

Вход в Telegram не нужен для:

- обычного веб-парса сайтов
- работы локального proxy frontend

Вход в Telegram нужен для:

- Telegram-источников, где нужен доступ через Telegram API
- приватных каналов, групп и веток
- `deep media check`
- строгой media-проверки
- отправки списка рабочих прокси в `Избранное`

Сессия пользователя хранится локально и в зашифрованном виде.

## Источники

Поддерживаются:

- веб-страницы с прямыми `https://t.me/proxy?...`
- публичные Telegram-страницы `https://t.me/s/...`
- Telegram API-источники вида `https://t.me/<channel>`
- Telegram API-источники вида `https://t.me/<channel>/<message_id>`
- Telegram API-ветки и сообщения из групп, если у аккаунта есть доступ

## Файлы результата

- `list/proxy_list.txt` — рабочие MTProto-прокси
- `list/all_list.txt` — все найденные MTProto-прокси
- `list/rejected_list.txt` — отсеянные MTProto-прокси
- `list/fast_list.txt` — быстрый поднабор лучших прокси, который приложение использует первым при старте
- `list/report.json` — подробный отчет

## Обновления

Новый релизный формат использует установщики:

- Windows: `MTProxyAutoSwitch-Setup.exe`
- macOS: `MTProxyAutoSwitch.pkg`

Переходный режим для старых клиентов сохранен:

- Windows-релиз по-прежнему публикует `MTProxyAutoSwitch.zip`
- старые portable-клиенты могут обновиться через legacy ZIP-канал
- после этого новые версии будут предпочитать установщик

На macOS основной канал обновления теперь тоже ориентирован на установщик. Старые сборки, которые не умели ставиться автоматически, могут потребовать один ручной переход на `.pkg`.

## Сборка Windows

Требование: установленный Inno Setup 6 (`ISCC.exe`).

```bat
build_release.bat
```

Результат:

```text
release-public\MTProxyAutoSwitch-Setup.exe
release-public\MTProxyAutoSwitch.zip
```

`MTProxyAutoSwitch-Setup.exe` — основной установщик. Он:

- ставит приложение в `%LOCALAPPDATA%\Programs\MTProxy AutoSwitch`
- добавляет ярлык в меню «Пуск»
- может добавить ярлык на рабочий стол
- регистрирует удаление приложения

`MTProxyAutoSwitch.zip` сохраняется как legacy-канал для старых portable-клиентов, чтобы переход на установочный формат не сломал автообновление.

## Сборка macOS

Сборку нужно выполнять на самой macOS.

```bash
chmod +x build_release_macos.sh
./build_release_macos.sh
```

Результат:

```text
release-macos/MTProxyAutoSwitch.app
release-macos/MTProxyAutoSwitch.pkg
```

`MTProxyAutoSwitch.pkg` — основной установщик для macOS. Он ставит приложение в `/Applications`, после чего оно появляется в списке приложений и Launchpad.

## Зависимости для сборки

- Python 3.11+
- `pip install -r requirements.txt`
- `pip install pyinstaller`

Windows:

- Inno Setup 6

macOS:

- Xcode Command Line Tools
- `pkgbuild`

Если в проекте используются `PySide6`, `telethon`, `cryptography`, `pillow`, они должны быть установлены в окружении сборки. Релизные скрипты ставят эти зависимости автоматически.

## Публикация релиза

Для GitHub Release теперь нужно выкладывать:

- Windows: `MTProxyAutoSwitch-Setup.exe`
- Windows legacy: `MTProxyAutoSwitch.zip`
- macOS: `MTProxyAutoSwitch.pkg`

Если хочешь сохранить ручную установку drag-and-drop для тестов на macOS, можно дополнительно прикладывать `.app` или отдельный `.dmg`, но основным каналом должен оставаться `.pkg`.

## Авторы

- оригинальный проект Flowseal: `https://github.com/Flowseal/tg-ws-proxy`
- форк и развитие: `https://github.com/pengvench/MTProxyAutoSwitch`
- Telegram автора: `https://t.me/peppe_poppo`
