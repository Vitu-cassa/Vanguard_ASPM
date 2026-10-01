// Servidor do alvo vulnerável — existe só para o DAST (OWASP ZAP) ter o que
// atacar. As rotas em routes/ continuam semeadas com falhas de propósito.
//
// SEGURANÇA: por padrão escuta apenas em 127.0.0.1. Não mude HOST para
// 0.0.0.0 fora de um container: /admin/exec executa comandos no sistema.
const express = require("express");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(require("./routes/login"));
app.use(require("./routes/search"));
app.use(require("./routes/profile"));
app.use(require("./routes/file"));
app.use(require("./routes/admin"));

// Página inicial com links e formulários: é por ela que o spider do ZAP
// descobre as rotas e os parâmetros que vai testar.
app.get("/", (req, res) => {
  res.type("text/html").send(`<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><title>mini-app</title></head>
<body>
  <h1>mini-app (alvo de testes do Vanguard)</h1>
  <ul>
    <li><a href="/search?q=notebook">Buscar produto</a></li>
    <li><a href="/profile/render?name=visitante">Perfil</a></li>
    <li><a href="/profile/redirect?to=/">Voltar ao início</a></li>
    <li><a href="/download/manual.txt">Baixar manual</a></li>
    <li><a href="/admin/exec?cmd=.">Listar arquivos (admin)</a></li>
    <li><a href="/admin/whoami">Quem sou eu (admin)</a></li>
  </ul>
  <form action="/search" method="get">
    <input name="q" value="mouse"><button>Buscar</button>
  </form>
  <form action="/login" method="post">
    <input name="email" value="aluno@fiap.com.br">
    <input name="password" type="password" value="senha123">
    <button>Entrar</button>
  </form>
</body></html>`);
});

const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT) || 3000;
app.listen(PORT, HOST, () => {
  console.log(`[mini-app] ouvindo em http://${HOST}:${PORT}`);
});
