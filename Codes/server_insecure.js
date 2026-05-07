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
    SELECT 'kamal','onpt666@4711'
    WHERE NOT EXISTS (
        SELECT 1 FROM users WHERE username='alice'
    )
    `);

    db.run(`
    INSERT INTO users(username,password)
    SELECT 'aastha','aastha@4933'
    WHERE NOT EXISTS (
        SELECT 1 FROM users WHERE username='bob'
    )
    `);
});


// Login API
app.post("/login",(req,res)=>{
    const {username,password}=req.body;

    db.get(
        "SELECT * FROM users WHERE username=? AND password=?",
        [username,password],
        (err,row)=>{
            if(err) return res.status(500).send(err);

            if(!row)
                return res.status(401).send("Invalid credentials");

            const token = jwt.sign({id:row.id},SECRET);
            res.json({token});
        }
    );
});

// Vulnerable API (IDOR/BOLA)
app.get("/user/:id",(req,res)=>{
    db.get(
        "SELECT * FROM users WHERE id="+req.params.id,
        (err,row)=>{
            res.json(row);
        }
    );
});

app.listen(3000,()=>{
    console.log("Server running on port 3000");
});