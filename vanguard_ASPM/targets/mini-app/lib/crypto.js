// Módulo de crypto — semeado com uso de MD5 para senha.
const crypto = require("crypto");

// CWE-327: MD5 para hash de senha (algoritmo fraco)
function hashPassword(pwd) {
  return crypto.createHash("md5").update(pwd).digest("hex");
}

module.exports = { hashPassword };
