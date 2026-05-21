'use strict';
const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');

// On Render, use /var/data for persistent disk (mount it there in the dashboard).
// Falls back to a local ./data directory for development.
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '../data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const DB_PATH = path.join(DATA_DIR, 'maze_bomber.db');
const db = new Database(DB_PATH);

// WAL mode: better concurrent read performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT NOT NULL,
    username_lower TEXT NOT NULL UNIQUE,
    password_hash  TEXT NOT NULL,
    created_at     INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    last_login     INTEGER
  );

  CREATE TABLE IF NOT EXISTS scores (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username    TEXT    NOT NULL,
    score       INTEGER NOT NULL,
    level       INTEGER NOT NULL DEFAULT 1,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    ts          INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_scores_ts      ON scores(ts);
  CREATE INDEX IF NOT EXISTS idx_scores_user    ON scores(user_id);
  CREATE INDEX IF NOT EXISTS idx_scores_score   ON scores(score DESC);
`);

module.exports = db;
