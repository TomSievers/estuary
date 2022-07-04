\c estuary

CREATE TABLE users (
    id SERIAL PRIMARY KEY NOT NULL,
    name VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(200) NOT NULL,
    write_permissions BOOLEAN NOT NULL
);

CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY NOT NULL,
    uid INTEGER NOT NULL,
    key VARCHAR(500) NOT NULL,
    CONSTRAINT api_key_user FOREIGN KEY(uid) REFERENCES users(id)
);

