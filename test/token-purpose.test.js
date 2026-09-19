const assert = require("node:assert/strict");
const { randomBytes } = require("node:crypto");
const { after, mock, test } = require("node:test");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

// Isola somente as fronteiras externas: sem .env, PostgreSQL ou SMTP reais.
mock.method(require("dotenv"), "config", () => ({}));
mock.method(Pool.prototype, "connect", () => { throw new Error("Banco real proibido no teste"); });
mock.method(Pool.prototype, "query", () => { throw new Error("Query não prevista no teste"); });
process.env.SMTP_HOST = "";
after(() => mock.restoreAll());

// Chave efêmera do processo de teste; nunca usa credenciais do ambiente.
process.env.JWT_SECRET = randomBytes(32).toString("hex");
const authMiddleware = require("../src/middlewares/authMiddleware");
const users = require("../src/controllers/UsuarioController");

function response() {
  return {
    statusCode: 200,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
}

function authenticate(token) {
  const req = { headers: token ? { authorization: `Bearer ${token}` } : {} };
  const res = response();
  let allowed = false;
  authMiddleware(req, res, () => { allowed = true; });
  return { req, res, allowed };
}

async function invoke(handler, body) {
  const res = response();
  await handler({ body }, res, (error) => { throw error; });
  return res;
}

test("token de recuperação não autoriza rotas comuns", () => {
  const token = jwt.sign(
    { kind: "pwdreset", id_usuario: 42, verif_id: 7 },
    process.env.JWT_SECRET,
    { expiresIn: "15m" }
  );
  const { res, allowed } = authenticate(token);
  assert.equal(allowed, false);
  assert.equal(res.statusCode, 401);
  assert.deepEqual(res.body, { erro: "Token inválido." });
});

// Caracterização: estes comportamentos já existiam antes da correção.
for (const [name, makeToken] of [
  ["ausente", () => null],
  ["malformado", () => "invalid-token"],
  ["assinatura inválida", () => jwt.sign({ id: 42 }, randomBytes(32))],
  ["expirado", () => jwt.sign({ id: 42 }, process.env.JWT_SECRET, { expiresIn: -1 })],
]) {
  test(`token ${name} não autoriza rotas comuns`, () => {
    const { res, allowed } = authenticate(makeToken());
    assert.equal(allowed, false);
    assert.equal(res.statusCode, 401);
  });
}

test("login mantém token sem kind aceito nas rotas comuns", async (t) => {
  const password = randomBytes(16).toString("hex");
  const user = {
    id_usuario: 42, nome: "Pessoa Teste", email: "pessoa@example.test",
    senha_hash: await bcrypt.hash(password, 10), email_verificado: true,
  };
  t.mock.method(Pool.prototype, "query", async () => ({ rows: [user] }));
  const login = await invoke(users.loginUsuario, { identificador: user.email, senha: password });
  assert.equal(login.statusCode, 200);
  assert.equal(typeof login.body.token, "string");
  const { req, allowed } = authenticate(login.body.token);
  assert.equal(allowed, true);
  assert.equal(req.user.id, 42);
  assert.equal(req.user.kind, undefined);
  assert.equal(req.user.exp - req.user.iat, 8 * 60 * 60);
  assert.equal(req.usuario, req.user);
});

test("token de acesso não autoriza redefinição de senha", async () => {
  const token = jwt.sign({ id: 42, id_usuario: 42 }, process.env.JWT_SECRET, { expiresIn: "8h" });
  const res = await invoke(users.forgotReset, { token, nova_senha: randomBytes(16).toString("hex") });
  assert.equal(res.statusCode, 401);
  assert.deepEqual(res.body, { erro: "Token inválido." });
});

test("recuperação legítima redefine senha, mas seu token não autoriza rotas comuns", async (t) => {
  const user = { id_usuario: 42, nome: "Pessoa Teste", email: "pessoa@example.test", email_verificado: true };
  const code = "123456"; // Código fictício, sem envio de e-mail.
  t.mock.method(Pool.prototype, "query", async (sql, params) => {
    if (sql.includes("SELECT id, id_usuario, codigo")) {
      return { rows: [{ id: 7, id_usuario: 42, codigo: code, tentativas: 0 }] };
    }
    if (sql.startsWith("UPDATE verificacoes_email")) return { rowCount: 1 };
    if (sql.startsWith("UPDATE usuarios SET senha_hash")) {
      user.senha_hash = params[0];
      return { rowCount: 1 };
    }
    if (sql.startsWith("SELECT * FROM usuarios")) return { rows: [user] };
    throw new Error("Query não prevista no teste");
  });

  const verification = await invoke(users.forgotVerify, { email: user.email, codigo: code });
  assert.equal(verification.statusCode, 200);
  assert.equal(typeof verification.body.token, "string");
  const token = verification.body.token;
  const payload = jwt.verify(token, process.env.JWT_SECRET);
  assert.equal(payload.kind, "pwdreset");
  assert.equal(payload.exp - payload.iat, 15 * 60);
  const auth = authenticate(token);
  assert.equal(auth.allowed, false);
  assert.equal(auth.res.statusCode, 401);

  const newPassword = randomBytes(16).toString("hex");
  const reset = await invoke(users.forgotReset, { token, nova_senha: newPassword });
  assert.equal(reset.statusCode, 200);
  assert.deepEqual(reset.body, { message: "Senha atualizada!" });
  const login = await invoke(users.loginUsuario, { identificador: user.email, senha: newPassword });
  assert.equal(login.statusCode, 200);
  assert.equal(authenticate(login.body.token).allowed, true);
});
