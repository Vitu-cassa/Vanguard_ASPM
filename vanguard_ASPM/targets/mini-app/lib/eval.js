// Módulo utilitário — code injection via eval.
function runFormula(userFormula) {
  // CWE-95: eval com input do usuário
  return eval(userFormula);
}

// CWE-94: construtor de função também é code injection
function compileHandler(bodyStr) {
  return new Function("req", "res", bodyStr);
}

module.exports = { runFormula, compileHandler };
