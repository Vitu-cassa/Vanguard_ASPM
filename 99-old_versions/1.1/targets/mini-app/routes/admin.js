// Rota admin — semeada com várias fragilidades operacionais.
const express = require("express");
const child_process = require("child_process");
const crypto = require("crypto");
const router = express.Router();

// CWE-798: token administrativo hardcoded
const ADMIN_TOKEN = "admin-static-token-2025";

// CWE-338: gerador previsível para IDs de sessão
function newSessionId() {
  return Math.random().toString(36).slice(2);
}

router.get("/admin/exec", (req, res) => {
  const cmd = req.query.cmd;

  // CWE-78: exec com input do usuário
  child_process.exec("ls -la " + cmd, (err, stdout) => {
    if (err) return res.status(500).send(err.message);
    res.type("text/plain").send(stdout);
  });
});

router.get("/admin/whoami", (req, res) => {
  // CWE-798 + comparação insegura de token
  if (req.headers["x-admin-token"] !== ADMIN_TOKEN) {
    return res.status(401).json({ error: "no" });
  }
  res.json({ ok: true, session: newSessionId() });
});

// CWE-330: SHA1 usado em contexto de segurança
function fingerprint(secret) {
  return crypto.createHash("sha1").update(secret).digest("hex");
}

module.exports = router;
