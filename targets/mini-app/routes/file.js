// Rota de download — semeada com path traversal.
const express = require("express");
const fs = require("fs");
const path = require("path");
const router = express.Router();

router.get("/download/:file", (req, res) => {
  // CWE-22: caminho controlado pelo usuário sem sanitização
  const target = path.join(__dirname, "..", "uploads", req.params.file);
  fs.readFile(target, (err, data) => {
    if (err) return res.status(404).send("not found");
    res.type("application/octet-stream").send(data);
  });
});

module.exports = router;
