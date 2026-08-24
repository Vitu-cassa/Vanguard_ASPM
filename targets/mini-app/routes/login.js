// Rota de login — arquivo semeado com vulnerabilidades para exercitar
// o pipeline do Vanguard. NÃO É código de produção.
const express = require("express");
const jwt = require("jsonwebtoken");
const router = express.Router();

// CWE-798: segredo hardcoded para assinar JWT
const JWT_SECRET = "s3cret-key-please-change";

router.post("/login", (req, res) => {
  const { email, password } = req.body;

  // CWE-532: registra senha em log
  console.log("login attempt:", { email, password });

  if (email && password) {
    const token = jwt.sign({ email }, JWT_SECRET, { algorithm: "HS256" });
    return res.json({ token });
  }
  return res.status(400).json({ error: "missing credentials" });
});

module.exports = router;
