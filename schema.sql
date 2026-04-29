CREATE DATABASE IF NOT EXISTS secure_vault;
USE secure_vault;

CREATE TABLE users (
  id                BIGINT AUTO_INCREMENT PRIMARY KEY,
  username          VARCHAR(100) UNIQUE NOT NULL,
  pw_salt_b64       VARCHAR(50) NOT NULL,
  recovery_salt_b64 VARCHAR(50) NOT NULL,
  auth_verifier_b64 VARCHAR(50) NOT NULL,
  created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE devices (
  id                     VARCHAR(100) PRIMARY KEY,
  username               VARCHAR(100) NOT NULL,
  device_name            VARCHAR(255),
  active                 BOOLEAN DEFAULT TRUE,
  fingerprint_hash_b64   VARCHAR(50),
  ip_hint_hash_b64       VARCHAR(50),
  public_key_jwk         JSON NOT NULL,
  enc_private_key_password JSON,
  enc_private_key_recovery JSON,
  created_at             TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (username) REFERENCES users(username)
    ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE notes (
  id               VARCHAR(100) PRIMARY KEY,
  owner_username   VARCHAR(100) NOT NULL,
  title            VARCHAR(255),
  encrypted_note   LONGTEXT NOT NULL,
  created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (owner_username) REFERENCES users(username)
    ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE note_access (
  note_id                VARCHAR(100) NOT NULL,
  device_id              VARCHAR(100) NOT NULL,
  wrapped_master_key_b64 TEXT NOT NULL,
  role                   ENUM('owner', 'viewer') DEFAULT 'viewer',
  fingerprint_hash_b64   VARCHAR(50),
  ip_hint_hash_b64       VARCHAR(50),
  PRIMARY KEY (note_id, device_id),
  FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE,
  FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);