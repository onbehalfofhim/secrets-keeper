# Secrets Keeper

Secrets Keeper — сервис для безопасного хранения пользовательских секретов.

Сервис предоставляет gRPC API для:

- регистрации и аутентификации пользователей;
- создания, получения, изменения и удаления секретов;
- хранения текстовых секретов;
- хранения login/password;
- хранения данных банковских карт;
- хранения бинарных файлов;
- загрузки и скачивания файлов через gRPC streaming;
- изоляции секретов между пользователями.

Для взаимодействия с сервером также предоставляется CLI-клиент `secrets-cli`.

---

## Архитектура

Проект построен по многослойной архитектуре.
Основные слои:

- **gRPC** — транспортный слой и преобразование protobuf-моделей;
- **Service** — бизнес-логика;
- **Repository** — работа с PostgreSQL;
- **Crypto** — шифрование и расшифровка данных;
- **Serializer** — сериализация структурированных секретов;
- **Auth** — хеширование паролей и JWT;
- **CLI** — пользовательский интерфейс клиента.

---

## Tech Stack

| Технология | Назначение |
|---|---|
| Go | основной язык |
| gRPC | взаимодействие клиента и сервера |
| Protocol Buffers | описание API |
| PostgreSQL | постоянное хранение данных |
| pgx/v5 | PostgreSQL driver и connection pool |
| pgxpool | пул соединений с PostgreSQL |
| JWT | аутентификация |
| AES-256-GCM | шифрование секретов |
| Cobra | CLI |
| golang-migrate | миграции БД |
| `encoding/json` | сериализация секретов |
| `slog` | логирование |
| Make | автоматизация команд |

---

## Требования к запуску

Для запуска проекта необходимы:

- Go 1.22+;
- PostgreSQL;
- `protoc`;
- Go plugins для генерации protobuf;
- `golang-migrate`;
- Make.

Проверить установленные версии:

```bash
go version
psql --version
protoc --version
migrate -version
```

---

## Установка

Клонировать репозиторий:

```bash
git clone git@github.com:onbehalfofhim/secrets-keeper.git
cd secrets-keeper
```

Установить зависимости:

```bash
go mod download
```

Установить параметры конфигурации приложения: см.раздел Configuration

---

## PostgreSQL

Создать базу данных:

```sql
CREATE DATABASE secrets_keeper;
```

При необходимости создать пользователя:

```sql
CREATE USER secrets_keeper WITH PASSWORD 'password';
```

И выдать права:

```sql
GRANT ALL PRIVILEGES ON DATABASE secrets_keeper TO secrets_keeper;
```

После создания БД необходимо выполнить миграции.

---

## Configuration

Конфигурация приложения задаётся через переменные окружения или аргументы командной строки.

| Переменная | Назначение | Аргумент командной строки |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | d |
| `JWT_SECRET` | секрет для подписи JWT | k |
| `ENCRYPTION_KEY` | ключ AES-256 | e |
| `RUN_ADDRESS` | адрес gRPC-сервера | a |
| `SHUTDOWN_TIMEOUT` | timeout для graceful shutdown | shutdown-timeout |
| `TLS_CERT_FILE` | сертификат для TLS | tls-cert |
| `TLS_KEY_FILE` | TLS ключ | tls-key |

Пример .env:

```env
RUN_ADDRESS=:50051
DATABASE_URL=postgresql://user:password@localhost:5432/secrets_keeper?sslmode=disable
JWT_SECRET=change-me
ENCRYPTION_KEY=...
SHUTDOWN_TIMEOUT=10s
TLS_CERT_FILE=certs/server.crt
TLS_KEY_FILE=certs/server.key
```

`ENCRYPTION_KEY` должен содержать ровно 32 байта для AES-256.

---

## Migrations

Миграции находятся в директории:

```text
migrations/
```

Применить миграции:

```bash
make migrate-up
```

Откатить последнюю миграцию:

```bash
make migrate-down
```

Проверить состояние миграций:

```bash
make migrate-version
```

Перед первым запуском сервера база данных должна быть мигрирована.

---

## Генерация protobuf

Описание gRPC API находится в:

```text
api/proto/
```

После изменения `.proto` файлов необходимо сгенерировать Go-код:

```bash
make proto
```

В результате будут сгенерированы protobuf types, gRPC client и gRPC server interfaces.

---

### TLS

gRPC соединение между CLI и сервером защищено TLS.

Для локальной разработки используется самоподписанный сертификат.

Сгенерировать сертификат:

```bash
openssl req \
  -x509 \
  -newkey rsa:2048 \
  -keyout certs/server.key \
  -out certs/server.crt \
  -days 365 \
  -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```
---

## Запуск сервера

Перед запуском необходимо:

0. Установить репозиторий
1. запустить PostgreSQL;
2. создать базу данных;
3. применить миграции;
4. настроить `.env`;
5. сгенерировать сертификат TLS.

После этого:

```bash
make run
```

или:

```bash
go run ./cmd/server
```

По умолчанию gRPC-сервер запускается на `localhost:50051`.

При получении SIGINT/SIGTERM выполняется graceful shutdown:

- прекращается приём новых RPC;
- завершаются активные RPC;
- останавливается gRPC-сервер;
- закрывается PostgreSQL connection;
- приложение завершается.

---

## Запуск CLI

CLI-приложение:

```bash
go run ./cmd/secrets-cli
```

Адрес gRPC-сервера можно передать через глобальный флаг:

```bash
go run ./cmd/secrets-cli --server localhost:50051 register
```

Основные команды:

```text
secrets-cli register
secrets-cli login
secrets-cli logout
secrets-cli version
secrets-cli secret ...
secrets-cli file ...
```

Справка:

```bash
go run ./cmd/secrets-cli --help
```

Версия:

```bash
go run ./cmd/secrets-cli version
```

Информация о версии и дате сборки записывается в бинарный файл на этапе сборки через `-ldflags`.

---

## Authentication

Для аутентификации используются JWT-токены.

### Registration

```bash
go run ./cmd/secrets-cli register
```

После успешной регистрации сервер возвращает ID пользователя.

### Login

```bash
go run ./cmd/secrets-cli login
```

При успешной авторизации сервер возвращает access token и время его действия. CLI сохраняет токен локально.

### Logout

```bash
go run ./cmd/secrets-cli logout
```

При logout локально сохранённый токен удаляется.

### JWT

Все защищённые RPC требуют:

```text
Authorization: Bearer <token>
```

Публичными являются:

```text
AuthService.Register
AuthService.Login
```

Остальные RPC требуют валидный JWT.

---

## Secret API

`SecretService` предоставляет операции:

```text
CreateSecret
GetSecret
UpdateSecret
ListSecrets
DeleteSecret
```

Поддерживаются следующие типы.

### Text

```text
TEXT
```

Обычный текстовый секрет.

### Login / Password

```text
LOGIN_PASSWORD
```

Содержит login и password.

### Bank Card

```text
BANK_CARD
```

Содержит номер карты, держателя, срок действия и CVV.

### Binary File

```text
BINARY_FILE
```

Metadata содержит имя файла и MIME type. Само содержимое передаётся через `BinaryService`.

### Encryption

Структурированные секреты:

```text
data
  ↓
JSON serialization
  ↓
AES-256-GCM encryption
  ↓
PostgreSQL
```

При получении:

```text
PostgreSQL
  ↓
AES-256-GCM decryption
  ↓
JSON deserialization
  ↓
response
```

Секреты хранятся в PostgreSQL только в зашифрованном виде.

---

## Binary API

Для работы с файлами используется отдельный `BinaryService`.

Основные RPC:

```text
UploadBinary
DownloadBinary
```

### Upload

`UploadBinary` использует client-side streaming.

Перед сохранением файл шифруется AES-256-GCM.

### Download

`DownloadBinary` использует server-side streaming.

Файл расшифровывается перед отправкой клиенту.

### Access control

Пользователь может:

- загрузить файл только в свой секрет;
- скачать только свой файл.

Попытка получить бинарный секрет другого пользователя возвращает `NotFound`.

---

## Testing

### Unit tests

Запустить все unit-тесты:

```bash
make test
```

Race detector:

```bash
make test-race
```

Покрытие:

```bash
make coverage
```

### Static analysis

```bash
make vet
```

### End-to-end scenarios

В `cmd/client/` находятся сценарии проверки основных бизнес-сценариев сервера.

Подробнее читай в `cmd/client/README.md`

### Запуск сценариев

Сценарии требуют запущенного сервера и настроенной PostgreSQL:

```bash
go run ./cmd/client
```
или
```bash
make scenarios
```

Успешное завершение:

```text
ALL SCENARIOS PASSED
ALL NEGATIVE gRPC TESTS PASSED
ALL SECURITY TESTS PASSED
```

---

## Makefile

Для основных операций проекта предусмотрены Make targets.

Посмотреть доступные команды:

```bash
make help
```

Перед использованием команд, связанных с сервером и PostgreSQL, необходимо настроить `.env`.

Makefile не содержит реальные credentials и не хранит секреты проекта.
