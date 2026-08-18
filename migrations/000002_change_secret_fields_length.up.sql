-- migrations/000002_change_secret_fields_length.up.sql

ALTER TABLE users
    ALTER COLUMN login TYPE VARCHAR(255),
    ALTER COLUMN password_hash TYPE VARCHAR(255);