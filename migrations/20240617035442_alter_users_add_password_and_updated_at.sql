-- Add migration script here
ALTER TABLE users ADD password VARCHAR(255) NOT NULL default ''
    , ADD updated_at timestamp default CURRENT_TIMESTAMP;