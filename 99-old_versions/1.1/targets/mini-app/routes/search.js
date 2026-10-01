// Rota de busca — semeada com SQL injection clássica.
const express = require("express");
const sqlite3 = require("sqlite3");
const router = express.Router();

const db = new sqlite3.Database(":memory:");

router.get("/search", (req, res) => {
  const q = req.query.q || "";

  // CWE-89: concatenação de input do usuário em SQL bruto
  const sql = "SELECT id, name FROM products WHERE name LIKE '%" + q + "%'";
  db.all(sql, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

module.exports = router;
