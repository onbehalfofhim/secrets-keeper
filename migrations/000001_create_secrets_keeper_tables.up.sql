-- migrations/000001_create_secrets_keeper_tables.up.sql

-- Создание таблицы пользователей
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    login TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Тип секрета
CREATE TYPE secret_type AS ENUM (
    'TEXT',
    'LOGIN_PASSWORD',
    'BANK_CARD',
    'BINARY_FILE'
);

-- Создание таблицы секретов
CREATE TABLE IF NOT EXISTS secrets (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL,
    type secret_type NOT NULL,
    encrypted_data BYTEA,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_secret_user
        FOREIGN KEY (owner_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

-- Индексы
CREATE INDEX idx_users_login
    ON users(login);

CREATE INDEX idx_secrets_owner
    ON secrets(owner_id);

CREATE INDEX idx_secrets_owner_type
    ON secrets(owner_id, type);