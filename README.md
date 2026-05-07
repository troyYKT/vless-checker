# VLESS Checker

Скрипт для массовой проверки VLESS-ссылок из CIDR/SNI списков.

Подходит для проверки конфигов на VPS, macOS и Windows. Скрипт запускает `xray` как временный VLESS-клиент, поднимает локальный SOCKS-прокси и проверяет доступность сервисов через каждый конфиг.

## Возможности

- выбор источника: `CIDR` или `SNI`;
- автоматическая загрузка списков с GitHub;
- fallback на локальные `.txt` файлы, если GitHub недоступен;
- режимы проверки:
  - `normal` — строгий режим;
  - `light` — лёгкий режим;
- проверка:
  - IP check;
  - Google;
  - YouTube;
  - Instagram;
  - Telegram;
  - WhatsApp;
- замер задержки конфига через `https://www.gstatic.com/generate_204`;
- сортировка рабочих ссылок по самой низкой задержке;
- опциональная мягкая проверка нагрузки;
- цветной вывод в терминале: `OK` зелёный, `FAIL` красный;
- сохранение чистых VLESS-ссылок для импорта в v2rayNG / Happ.

## Требования

Нужно установить:

- Python 3.10+
- curl
- xray-core
- git, если проект скачивается с GitHub

Проверка:

```bash
python3 --version
curl --version
xray version
```

На Windows вместо `python3` обычно используется:

```powershell
python --version
```

## Установка на VPS Ubuntu/Debian

```bash
apt update
apt install -y git curl unzip ca-certificates python3
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
```

Скачать проект:

```bash
cd /root
git clone https://github.com/troyykt/vless-checker.git
cd vless-checker
```

Создать папку для локальных списков:

```bash
mkdir -p /root/vless_checker
cp WHITE-CIDR-RU-all.txt /root/vless_checker/
cp WHITE-SNI-RU-all.txt /root/vless_checker/
```

Запуск:

```bash
python3 check_vless_bulk.py
```

## Установка на macOS

Установить зависимости через Homebrew:

```bash
brew install git python3 xray
```

Скачать проект:

```bash
cd ~
git clone https://github.com/troyykt/vless-checker.git
cd vless-checker
```

Создать папку для локальных списков:

```bash
mkdir -p ~/vless_checker
cp WHITE-CIDR-RU-all.txt ~/vless_checker/
cp WHITE-SNI-RU-all.txt ~/vless_checker/
```

Запуск:

```bash
python3 check_vless_bulk.py --local-dir ~/vless_checker
```

## Установка на Windows PowerShell

Перейти в папку проекта:

```powershell
cd C:\Users\troya\vless_checker
```

Скачать и распаковать Xray:

```powershell
mkdir xray
Invoke-WebRequest -Uri "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip" -OutFile "xray.zip"
Expand-Archive -Force "xray.zip" "xray"
```

Добавить Xray в PATH для текущего окна PowerShell:

```powershell
$env:Path = "$PWD\xray;$env:Path"
```

Проверить:

```powershell
xray version
```

Запуск:

```powershell
python .\check_vless_bulk.py --local-dir .
```

## Основной запуск

При запуске без `--input` скрипт предложит выбрать источник:

```text
1) CIDR
2) SNI
3) Enter custom URL or local file path
```

Затем предложит выбрать режим:

```text
1) normal - strict
2) light  - soft
```

## Режимы проверки

### Normal

Строгий режим. Ссылка сохраняется только если работают:

```text
IP + Google + YouTube + Instagram + Telegram + WhatsApp
```

Запуск без меню:

```bash
python3 check_vless_bulk.py --mode normal
```

На Windows:

```powershell
python .\check_vless_bulk.py --mode normal --local-dir .
```

### Light

Лёгкий режим. Ссылка сохраняется если работают:

```text
IP + Google + YouTube
```

Instagram, Telegram и WhatsApp проверяются и показываются в выводе, но не отсекают конфиг.

Запуск без меню:

```bash
python3 check_vless_bulk.py --mode light
```

На Windows:

```powershell
python .\check_vless_bulk.py --mode light --local-dir .
```

## Лимит и смещение

Проверить все ссылки:

```bash
python3 check_vless_bulk.py --limit 0
```

Проверить первые 30:

```bash
python3 check_vless_bulk.py --limit 30
```

Проверить ссылки 31–60:

```bash
python3 check_vless_bulk.py --offset 30 --limit 30
```

Проверить ссылки 61–90:

```bash
python3 check_vless_bulk.py --offset 60 --limit 30
```

## Параллельность и таймаут

По умолчанию используются быстрые настройки:

```bash
--workers 12
--service-workers 6
--timeout 8
```

Более мягкий запуск:

```bash
python3 check_vless_bulk.py --workers 8 --service-workers 5 --timeout 8
```

Если много ложных `FAIL`, увеличьте таймаут:

```bash
python3 check_vless_bulk.py --timeout 12
```

## Проверка нагрузки

По умолчанию нагрузочный тест выключен.

Включить мягкую проверку нагрузки:

```bash
python3 check_vless_bulk.py --mode light --load-test
```

На Windows:

```powershell
python .\check_vless_bulk.py --mode light --local-dir . --load-test
```

По умолчанию нагрузочный тест делает:

```text
10 лёгких запросов
3 параллельно
URL: https://www.gstatic.com/generate_204
```

Настроить мягче:

```bash
python3 check_vless_bulk.py --load-test --load-requests 5 --load-workers 2
```

Сделать нагрузку обязательной для сохранения:

```bash
python3 check_vless_bulk.py --load-test --load-required --load-min-success-rate 0.8
```

## Выходные файлы

Для CIDR normal:

```text
working_vless_CIDR_normal.txt
vless_check_results_CIDR_normal.csv
```

Для CIDR light:

```text
working_vless_CIDR_light.txt
vless_check_results_CIDR_light.csv
```

Для SNI normal:

```text
working_vless_SNI_normal.txt
vless_check_results_SNI_normal.csv
```

Для SNI light:

```text
working_vless_SNI_light.txt
vless_check_results_SNI_light.csv
```

Файлы `working_vless_*.txt` содержат чистые VLESS-ссылки, пригодные для импорта в v2rayNG / Happ.

CSV-файлы содержат подробные результаты проверки.

## Локальные списки

Если GitHub недоступен, скрипт использует локальные файлы.

На VPS по умолчанию:

```text
/root/vless_checker/WHITE-CIDR-RU-all.txt
/root/vless_checker/WHITE-SNI-RU-all.txt
```

На macOS по умолчанию:

```text
~/vless_checker/WHITE-CIDR-RU-all.txt
~/vless_checker/WHITE-SNI-RU-all.txt
```

На Windows лучше запускать так, чтобы локальные `.txt` лежали рядом со скриптом:

```powershell
python .\check_vless_bulk.py --local-dir .
```

Можно явно указать папку:

```bash
python3 check_vless_bulk.py --local-dir /path/to/folder
```

## Примеры

### Быстрая проверка CIDR в лёгком режиме

```bash
python3 check_vless_bulk.py --mode light --limit 30
```

### Строгая проверка всех CIDR

```bash
python3 check_vless_bulk.py --mode normal --limit 0
```

### Проверка SNI через меню

```bash
python3 check_vless_bulk.py
```

Выбрать `SNI`, затем выбрать режим.

### Проверка своего файла

```bash
python3 check_vless_bulk.py --input links.txt --mode light
```

### Проверка своего URL

```bash
python3 check_vless_bulk.py --input "https://example.com/sub.txt" --mode light
```

## Обновление проекта

На VPS/macOS:

```bash
cd ~/vless-checker 2>/dev/null || cd /root/vless-checker
git pull
```

На Windows PowerShell:

```powershell
cd C:\Users\troya\vless_checker
git pull
```

## Примечания

- `cfg_ms` — это не чистый ping до сервера. Это практическая задержка через VLESS до `https://www.gstatic.com/generate_204`.
- `ip=1(200)` означает, что через VLESS удалось открыть IP-check сервис.
- `wa=1(400)` может быть нормальным: WhatsApp часто отвечает кодом `400`, но это всё равно значит, что домен доступен.
- В режиме белых списков результат на VPS и на мобильной сети может отличаться, потому что маршруты до VLESS-сервера разные.
