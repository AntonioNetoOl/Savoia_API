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

function mockMember(t, fields, { recentCharges = [], openCharge = null } = {}) {
  const user = { id_usuario: 42, nome: "Pessoa Teste", email: "pessoa@example.test", ...fields };
  t.mock.method(Pool.prototype, "query", async (sql) => {
    if (!/^\s*SELECT\b/.test(sql)) throw new Error("Escrita não permitida no resumo");
    if (/FROM usuarios u/.test(sql)) return { rows: [user] };
    if (/FROM cobrancas\b/.test(sql)) return { rows: /AS due_date/.test(sql) ? (openCharge ? [openCharge] : []) : recentCharges };
    if (/FROM (fidelidade_movimentos|brindes_fidelidade_socio)\b/.test(sql)) return { rows: [] };
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

test("resumo informa calendário da cobrança em atraso sem mudar o vínculo", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: new Date("2026-05-13T15:00:00.000Z") });
  mockMember(t, { id_socio: 7, status_socio: "active" }, {
    openCharge: { id_cobranca: "11", status_cobranca: "pending", due_date: "2026-05-10" },
  });
  const res = await invoke(getMemberSummary);
  assert.deepEqual(res.body.payments.chargeTiming, {
    chargeId: "11", chargeStatus: "pending", dueDate: "2026-05-10",
    asOfDate: "2026-05-13", timeZone: "America/Sao_Paulo", daysOverdue: 3, phase: "grace_period",
    firstReminderDate: "2026-05-11", lastReminderDate: "2026-05-17", inactiveDate: "2026-05-18",
  });
  assert.equal(res.body.memberStatus, "socio_ativo");
});

for (const date of ["2026-05-09", "2026-05-10"]) {
  test(`cobrança não está em atraso em ${date}`, async (t) => {
    t.mock.timers.enable({ apis: ["Date"], now: new Date(`${date}T15:00:00.000Z`) });
    mockMember(t, { id_socio: 7, status_socio: "active" }, {
      openCharge: { id_cobranca: "11", status_cobranca: "scheduled", due_date: "2026-05-10" },
    });
    const res = await invoke(getMemberSummary);
    assert.equal(res.body.payments.chargeTiming.daysOverdue, 0);
    assert.equal(res.body.payments.chargeTiming.phase, "not_overdue");
  });
}

test("oitavo dia encerra a tolerância da cobrança sem inativar a associação na leitura", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: new Date("2026-05-18T03:00:00.000Z") });
  mockMember(t, { id_socio: 7, status_socio: "active" }, {
    openCharge: { id_cobranca: "11", status_cobranca: "pending", due_date: "2026-05-10" },
  });
  const res = await invoke(getMemberSummary);
  assert.equal(res.body.payments.chargeTiming.daysOverdue, 8);
  assert.equal(res.body.payments.chargeTiming.phase, "grace_expired");
  assert.equal(res.body.memberStatus, "socio_ativo");
});

for (const [now, dueDate, asOfDate, daysOverdue, phase, inactiveDate] of [
  ["2026-05-11T03:00:00.000Z", "2026-05-10", "2026-05-11", 1, "grace_period", "2026-05-18"],
  ["2026-05-18T02:59:59.999Z", "2026-05-10", "2026-05-17", 7, "grace_period", "2026-05-18"],
  ["2027-01-05T03:00:00.000Z", "2026-12-28", "2027-01-05", 8, "grace_expired", "2027-01-05"],
  ["2028-03-01T03:00:00.000Z", "2028-02-25", "2028-03-01", 5, "grace_period", "2028-03-04"],
]) {
  test(`calendário do resumo usa o dia de São Paulo em ${now}`, async (t) => {
    t.mock.timers.enable({ apis: ["Date"], now: new Date(now) });
    mockMember(t, { id_socio: 7, status_socio: "active" }, {
      openCharge: { id_cobranca: "11", status_cobranca: "pending", due_date: dueDate },
    });
    const timing = (await invoke(getMemberSummary)).body.payments.chargeTiming;
    assert.deepEqual([timing.asOfDate, timing.daysOverdue, timing.phase, timing.inactiveDate], [asOfDate, daysOverdue, phase, inactiveDate]);
  });
}

for (const fields of [{ id_socio: null }, { id_socio: 7, status_socio: "active" }]) {
  test(`sem cobrança em aberto, calendário é nulo: vínculo ${fields.id_socio ?? "ausente"}`, async (t) => {
    mockMember(t, fields, { recentCharges: [
      { id_cobranca: "14", status_cobranca: "refunded", due_at: "2026-05-14" },
      { id_cobranca: "13", status_cobranca: "cancelled", due_at: "2026-05-13" },
      { id_cobranca: "12", status_cobranca: "paid", due_at: "2026-05-12" },
    ] });
    assert.equal((await invoke(getMemberSummary)).body.payments.chargeTiming, null);
  });
}

test("cobrança antiga que falhou tem calendário próprio, separado das seis recentes e da reativação", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: new Date("2026-05-20T15:00:00.000Z") });
  mockMember(t, { id_socio: 7, status_socio: "active", data_ativacao: "2026-05-20T12:00:00.000Z" }, {
    recentCharges: [
      { id_cobranca: "30", status_cobranca: "pending", due_at: "2026-06-20", competencia_label: "06/2026" },
      ...[29, 28, 27, 26, 25].map((id) => ({ id_cobranca: String(id), status_cobranca: "paid", due_at: "2026-05-20" })),
    ],
    openCharge: { id_cobranca: "11", status_cobranca: "failed", due_date: "2026-05-10", tolerance_until: "2026-05-30" },
  });
  const res = await invoke(getMemberSummary);
  assert.deepEqual(res.body.payments, {
    title: "Pagamentos", description: "Acompanhe histórico, próximos lançamentos e cartões cadastrados.",
    nextChargeLabel: "06/2026", nextChargeDueAt: "2026-06-20", latestStatus: "pending",
    recurrenceEnabled: false, subscriptionStatus: null,
    chargeTiming: {
      chargeId: "11", chargeStatus: "failed", dueDate: "2026-05-10", asOfDate: "2026-05-20",
      timeZone: "America/Sao_Paulo", daysOverdue: 10, phase: "grace_expired",
      firstReminderDate: "2026-05-11", lastReminderDate: "2026-05-17", inactiveDate: "2026-05-18",
    },
  });
  assert.equal(res.body.memberStatus, "socio_ativo");
});

test("calendário de cobrança não desbloqueia nem ativa vínculo bloqueado", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: new Date("2026-05-13T15:00:00.000Z") });
  mockMember(t, { id_socio: 7, status_socio: "blocked" }, {
    openCharge: { id_cobranca: "11", status_cobranca: "pending", due_date: "2026-05-10" },
  });
  const res = await invoke(getMemberSummary);
  assert.equal(res.body.payments.chargeTiming.phase, "grace_period");
  assert.equal(res.body.memberStatus, "socio_inativo");
});

test("vencimento inválido não gera um calendário financeiro falso", async (t) => {
  mockMember(t, { id_socio: 7, status_socio: "active" }, {
    openCharge: { id_cobranca: "11", status_cobranca: "pending", due_date: "2026-02-30" },
  });
  await assert.rejects(invoke(getMemberSummary), RangeError);
});

test("falha ao consultar cobrança em aberto é propagada pelo resumo", async (t) => {
  const failure = new Error("Consulta de cobrança de teste indisponível");
  t.mock.method(Pool.prototype, "query", async (sql) => {
    if (/FROM usuarios u/.test(sql)) return { rows: [{ id_usuario: 42, id_socio: 7, status_socio: "active" }] };
    if (/AS due_date/.test(sql)) throw failure;
    if (/^\s*SELECT\b/.test(sql)) return { rows: [] };
    throw new Error("Escrita não permitida no resumo");
  });
  await assert.rejects(invoke(getMemberSummary), (error) => error === failure);
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
