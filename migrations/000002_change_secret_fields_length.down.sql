-- migrations/000002_change_secret_fields_length.down.sql

ALTER TABLE users
    ALTER COLUMN login TYPE TEXT,
    ALTER COLUMN password_hash TYPE TEXT;