const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();
app.use(bodyParser.json());
app.use(cors());

const SECRET = "mscproject";

const db = new sqlite3.Database("./database.db");

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    `);

    db.run(`
        INSERT INTO users(username,password)
        SELECT 'user','password'
        WHERE NOT EXISTS (
            SELECT 1 FROM users WHERE username='user'
        )
    `);

    db.run(`
        INSERT INTO users(username,password)
        SELECT 'kamal','onpt66604711'
        WHERE NOT EXISTS (
            SELECT 1 FROM users WHERE username='kamal'
        )
    `);

    db.run(`
        INSERT INTO users(username,password)
        SELECT 'aastha','aastha@4933'
        WHERE NOT EXISTS (
            SELECT 1 FROM users WHERE username='aastha'
        )
    `);
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.get(
        "SELECT * FROM users WHERE username=? AND password=?",
        [username, password],
        (err, row) => {
            if (err) return res.status(500).send(err.message);
            if (!row) return res.status(401).json({ message: "Invalid credentials" });

            const token = jwt.sign(
                { id: row.id, username: row.username },
                SECRET,
                { expiresIn: "1h" }
            );

            res.json({ token });
        }
    );
});

// authentication middleware
function verifyToken(req, res, next) {
    const authHeader = req.headers["authorization"];

    if (!authHeader) {
        return res.status(401).json({ message: "Token required" });
    }

    const parts = authHeader.split(" ");
    if (parts.length !== 2 || parts[0] !== "Bearer") {
        return res.status(401).json({ message: "Invalid authorization format" });
    }

    const token = parts[1];

    jwt.verify(token, SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: "Invalid or expired token" });
        }

        req.user = decoded;
        next();
    });
}

// secure endpoint
app.get("/user/:id", verifyToken, (req, res) => {
    const requestedId = parseInt(req.params.id, 10);

    // object-level authorization
    if (req.user.id !== requestedId) {
        return res.status(403).json({ message: "Forbidden: cannot access another user's data" });
    }

    db.get(
        "SELECT id, username FROM users WHERE id=?",
        [requestedId],
        (err, row) => {
            if (err) return res.status(500).send(err.message);
            if (!row) return res.status(404).json({ message: "User not found" });

            res.json(row);
        }
    );
});

app.listen(3000, () => {
    console.log("Secure server running on port 3000");
});