// Rota de perfil — XSS via innerHTML + open redirect.
const express = require("express");
const router = express.Router();

router.get("/profile/render", (req, res) => {
  const name = req.query.name || "guest";
  // CWE-79: HTML interpolando input do usuário sem escape
  const html = "<html><body><h1>Olá, " + name + "</h1></body></html>";
  res.type("text/html").send(html);
});

router.get("/profile/redirect", (req, res) => {
  const to = req.query.to;
  // CWE-601: open redirect
  res.redirect(to);
});

module.exports = router;
