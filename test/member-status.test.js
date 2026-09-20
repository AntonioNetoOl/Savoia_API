const assert = require("node:assert/strict");
const { after, mock, test } = require("node:test");
const { Pool } = require("pg");

mock.method(require("dotenv"), "config", () => ({}));
mock.method(Pool.prototype, "connect", () => { throw new Error("Banco real proibido no teste"); });
mock.method(Pool.prototype, "query", () => { throw new Error("Query não prevista no teste"); });
after(() => mock.restoreAll());

const { getMemberSummary } = require("../src/controllers/MemberController");
const { getMe } = require("../src/controllers/MenuController");
const { createAssociationRequest } = require("../src/controllers/MemberAssociationController");

async function invoke(handler, req = { user: { id: 42 } }) {
  const res = {
    statusCode: 200,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
  await handler(req, res, (error) => { throw error; });
  return res;
}

function mockMember(t, fields) {
  const user = { id_usuario: 42, nome: "Pessoa Teste", email: "pessoa@example.test", ...fields };
  t.mock.method(Pool.prototype, "query", async (sql) => {
    if (/FROM usuarios u/.test(sql)) return { rows: [user] };
    if (/FROM (cobrancas|fidelidade_movimentos|brindes_fidelidade_socio)\b/.test(sql)) return { rows: [] };
    throw new Error("Query não prevista no teste");
  });
}

test("conta ativa sem vínculo continua não sócia no resumo e menu", async (t) => {
  mockMember(t, { status: "ATIVO", id_socio: null, status_socio: null });
  for (const handler of [getMemberSummary, getMe]) {
    const res = await invoke(handler);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.memberStatus, "nao_socio");
  }
});

test("vínculo bloqueado aparece inativo no resumo e menu", async (t) => {
  mockMember(t, { status: "ATIVO", id_socio: 7, status_socio: "blocked" });
  for (const handler of [getMemberSummary, getMe]) {
    const res = await invoke(handler);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.memberStatus, "socio_inativo");
  }
});

for (const [status, expected, title] of [
  [null, "nao_socio", "Não associado"],
  ["active", "socio_ativo", "Associação ativa"],
  ["inactive", "socio_inativo", "Associação inativa"],
  ["pending_validation", "socio_inativo", "Associação inativa"],
  ["blocked", "socio_inativo", "Associação inativa"],
  ["cancelled", "socio_inativo", "Associação inativa"],
]) {
  test(`vínculo ${status ?? "ausente"} independe do status da conta e da origem`, async (t) => {
    for (const accountStatus of ["PENDENTE_VERIFICACAO", "PROCESSANDO_CONFIRMACAO", "ATIVO", "NAO_ENCONTRADO", "INATIVO"]) {
      for (const origin of status ? ["app_new", "legacy_import", "manual_admin"] : [null]) {
        mockMember(t, {
          status: accountStatus, id_socio: status ? 7 : null, status_socio: status,
          numero_socio: status ? "TEST-7" : null, tipo_origem: origin,
        });
        const summary = await invoke(getMemberSummary);
        const menu = await invoke(getMe);
        assert.equal(summary.statusCode, 200);
        assert.equal(menu.statusCode, 200);
        assert.equal(summary.body.memberStatus, expected);
        assert.deepEqual(menu.body, {
          id: 42, name: "Pessoa Teste", email: "pessoa@example.test",
          memberStatus: expected, memberNumber: status ? "TEST-7" : null, memberOrigin: origin,
        });
        assert.equal(summary.body.association.linked, status !== null);
        assert.equal(summary.body.association.title, title);
        assert.deepEqual(Object.keys(summary.body).sort(), [
          "association", "benefits", "loyalty", "memberStatus", "payments", "plan", "statusCard", "user",
        ]);
      }
    }
  });
}

for (const handler of [getMemberSummary, getMe]) {
  test(`${handler.name} preserva identificação obrigatória e usuário inexistente`, async (t) => {
    const missingIdentity = await invoke(handler, {});
    assert.equal(missingIdentity.statusCode, 401);
    assert.deepEqual(missingIdentity.body, { erro: "Usuário não identificado no token." });
    t.mock.method(Pool.prototype, "query", async () => ({ rows: [] }));
    const missingUser = await invoke(handler);
    assert.equal(missingUser.statusCode, 404);
    assert.deepEqual(missingUser.body, { erro: "Usuário não encontrado." });
  });

  test(`${handler.name} propaga falha de consulta sem devolver não sócio`, async (t) => {
    const failure = new Error("Consulta de teste indisponível");
    t.mock.method(Pool.prototype, "query", async () => { throw failure; });
    await assert.rejects(invoke(handler), (error) => error === failure);
  });
}

test("vínculo bloqueado continua inelegível para solicitar associação", async (t) => {
  t.mock.method(Pool.prototype, "connect", async () => ({
    async query(sql) {
      if (["BEGIN", "ROLLBACK", "COMMIT"].includes(sql)) return { rows: [] };
      if (/FROM usuarios\b/.test(sql)) return { rows: [{ id_usuario: 42 }] };
      if (/FROM planos_associacao\b/.test(sql)) return { rows: [{ id_plano: 3, codigo_plano: "mutley" }] };
      if (/FROM socios\b/.test(sql)) return { rows: [{ id_socio: 7, status_socio: "blocked" }] };
      throw new Error("Escrita não permitida neste cenário");
    },
    release() {},
  }));
  const res = await invoke(createAssociationRequest, { user: { id: 42 }, body: { planCode: "mutley" } });
  assert.equal(res.statusCode, 409);
  assert.deepEqual(res.body, {
    erro: "O estado atual da associação exige análise da Savóia.",
    code: "member_status_not_eligible",
  });
});
