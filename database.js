const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");

const db = new sqlite3.Database("./database.db", (err) => {
  if (err) {
    console.log("Errore di connessione nel DB");
  } else {
    console.log("Connessione al DB effettuata");
    initializeDatabase();
  }
});

function initializeDatabase() {
  db.serialize(async () => {
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        secret TEXT
      )
      `);

    db.get(
      "SELECT * FROM users WHERE username = 'admin' ",
      async (err, row) => {
        if (!row) {
          //Passwords stored with bcrypt, a slow, salted hash which makes brute-force attacks expensive and defeats the rainbow-table attacks
          const admin_password = process.env.ADMIN_PASSWORD || "admin_weak_password123"; 
          const hash = await bcrypt.hash(admin_password, 10);
          db.run(
            "INSERT INTO users (username, password, role, secret) VALUES (?, ?, ?, ?)",
            ["admin", hash, "admin", ""],
          );
          console.log("Utente admin aggiunto al DB di default");
        }
      },
    );
  });
}

module.exports = db;
