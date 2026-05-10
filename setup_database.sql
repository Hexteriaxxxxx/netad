-- ================================================
-- NETAD Security System — Database Setup Script
-- Run once: psql -U postgres -d netad -f setup_database.sql
-- ================================================

-- Create database (run this manually in psql first if needed)
-- CREATE DATABASE netad;

-- ================================================
-- TABLES
-- ================================================

-- Users table
-- password_hash is VARCHAR(255) to support bcrypt (60 chars) and argon2 (95+ chars)
CREATE TABLE IF NOT EXISTS users (
    id           SERIAL PRIMARY KEY,
    username     VARCHAR(50)  UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role         VARCHAR(50)  NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    created_at   TIMESTAMP DEFAULT NOW()
);

-- Whitelist table
CREATE TABLE IF NOT EXISTS whitelist (
    id         SERIAL PRIMARY KEY,
    ip         VARCHAR(45) UNIQUE NOT NULL,
    label      VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Blacklist table
CREATE TABLE IF NOT EXISTS blacklist (
    id            SERIAL PRIMARY KEY,
    ip            VARCHAR(45) UNIQUE NOT NULL,
    type          VARCHAR(20) NOT NULL DEFAULT 'temporary',
    blocked_until TIMESTAMP,
    created_at    TIMESTAMP DEFAULT NOW()
);

-- Logs table
CREATE TABLE IF NOT EXISTS logs (
    id        SERIAL PRIMARY KEY,
    username  VARCHAR(50),
    ip        VARCHAR(45),
    result    VARCHAR(20),
    reason    VARCHAR(200),
    timestamp TIMESTAMP DEFAULT NOW()
);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id         SERIAL PRIMARY KEY,
    username   VARCHAR(50) NOT NULL,
    ip         VARCHAR(45),
    role       VARCHAR(50),
    token      VARCHAR(255) UNIQUE NOT NULL,
    last_seen  TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Used tokens table (one-time session tokens — TOCTOU-safe via unique constraint)
CREATE TABLE IF NOT EXISTS used_tokens (
    id      SERIAL PRIMARY KEY,
    token   VARCHAR(255) UNIQUE NOT NULL,
    used_at TIMESTAMP DEFAULT NOW()
);

-- AI anomaly logs
CREATE TABLE IF NOT EXISTS ai_logs (
    id          SERIAL PRIMARY KEY,
    ip          VARCHAR(45),
    username    VARCHAR(50),
    description VARCHAR(200),
    score       FLOAT,
    flagged     BOOLEAN DEFAULT FALSE,
    timestamp   TIMESTAMP DEFAULT NOW()
);

-- AI Security Guard chat logs
CREATE TABLE IF NOT EXISTS chat_logs (
    id        SERIAL PRIMARY KEY,
    role      VARCHAR(20) NOT NULL,  -- 'user', 'assistant', 'system'
    message   TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT NOW()
);

-- Device keys table (Web Crypto + IndexedDB device-based auth)
CREATE TABLE IF NOT EXISTS device_keys (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(50)  NOT NULL,
    device_id   VARCHAR(255) UNIQUE NOT NULL,
    public_key  TEXT NOT NULL,
    label       VARCHAR(255) DEFAULT 'Unknown Device',
    status      VARCHAR(20)  DEFAULT 'pending',  -- pending, approved, rejected
    created_at  TIMESTAMP DEFAULT NOW(),
    approved_at TIMESTAMP
);

-- ================================================
-- INDEXES
-- ================================================
CREATE INDEX IF NOT EXISTS idx_logs_timestamp    ON logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_ip           ON logs(ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_blacklist_ip      ON blacklist(ip);
CREATE INDEX IF NOT EXISTS idx_whitelist_ip      ON whitelist(ip);
CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);
CREATE INDEX IF NOT EXISTS idx_used_tokens_token ON used_tokens(token);
CREATE INDEX IF NOT EXISTS idx_chat_logs_ts      ON chat_logs(timestamp DESC);

-- ================================================
-- NOTE ON USERS
-- Do NOT insert users with plaintext passwords here.
-- Run: python security/generate_keys.py
-- That script reads passwords from .env and stores bcrypt hashes.
-- ================================================
