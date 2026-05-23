const sqlite3 = require("sqlite3").verbose();
const fs = require("fs");
const path = require("path");

const dbPath = process.env.DATABASE_PATH || path.join(__dirname, "database.sqlite");
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new sqlite3.Database(dbPath);

db.serialize(() => {

    db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        games_played INTEGER DEFAULT 0,
        highest_score INTEGER DEFAULT 0,
        highest_level INTEGER DEFAULT 0
    )
    `);

    db.run(`
    CREATE TABLE IF NOT EXISTS scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        score INTEGER,
        level INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    `);

    db.all("PRAGMA table_info(users)", (err, rows) => {
        if(rows){
            const cols = rows.map(r => r.name);
            if(!cols.includes("games_played")){
                db.run("ALTER TABLE users ADD COLUMN games_played INTEGER DEFAULT 0");
            }
            if(!cols.includes("highest_score")){
                db.run("ALTER TABLE users ADD COLUMN highest_score INTEGER DEFAULT 0");
            }
            if(!cols.includes("highest_level")){
                db.run("ALTER TABLE users ADD COLUMN highest_level INTEGER DEFAULT 0");
            }
        }
    });

    db.run(`CREATE INDEX IF NOT EXISTS idx_scores_user ON scores(user_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_scores_score ON scores(score)`);

});

module.exports = db;
