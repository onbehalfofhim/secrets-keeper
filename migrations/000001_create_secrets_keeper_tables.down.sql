-- Удаление таблиц
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS secrets;

DROP INDEX IF EXISTS idx_users_login;
DROP INDEX IF EXISTS idx_secrets_owner;
DROP INDEX IF EXISTS idx_secrets_owner_type;