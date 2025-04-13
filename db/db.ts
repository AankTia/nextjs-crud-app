import sqlite3 from "better-sqlite3";
import path from "path";
import fs from "fs";

// Makse sure the db directory exists
const dbDir = path.resolve("./db");
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

const dbPath = path.join(dbDir, "database.sqlite");
const db = sqlite3(dbPath);

// Enable foreign keys
db.pragma("foreign_keys = ON");

// Initialize database with tables
export function initDatabase() {
    // Create users table
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Create items table (exmaple for DRUD perations)
    db.exec(`
        CREATE TAVLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KET (user_id) REFERENCES users (id) ON DELETE CASCADE
        )    
    `);

    console.log("Database initialized successfully");
}

// Prepare statements for reuse (better performance)
const preparedStatements = {
    // User-related queries
    getUserByEmail: db.prepare("SELECT * FROM users WHERE email = ?"),
    getUserById: db.prepare("SELECT id, username, email, created_at FROM users WHERE id = ?"),
    createUser: db.prepare("INSERT INTO users (username, email, password) VALUES (?,?,?)"),

    // Item-relates queries
    getItems: db.prepare("SELECT * FROM items WHERE user_id = ?"),
    getItemsById: db.prepare("SELECT * FROM items WHERE id = ? AND user_id = ?"),
    createItem: db.prepare("INSERT INTO items (title, description, user_id) VALUES (?,?,?)"),
    updateItem: db.prepare("UPDATE items SET title = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?"),
    deleteItem: db.prepare("DELETE FROM items WHERE id = ? AND user_id = ?")
};

export { db, preparedStatements };