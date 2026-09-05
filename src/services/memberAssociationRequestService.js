// src/services/memberAssociationRequestService.js
const db = require("../config/DB");

const REQUESTABLE_MEMBER_STATUSES = new Set(["inactive", "pending_validation"]);

class MemberAssociationRequestError extends Error {
  constructor({ code, message, status = 400 }) {
    super(message);
    this.name = "MemberAssociationRequestError";
    this.code = code;
    this.status = status;
  }
}

function inferRequestType(member) {
  if (!member) return "association";

  const neverActivated =
    !member.data_ativacao &&
    !member.numero_socio &&
    !member.id_socio_legado &&
    member.tipo_origem === "app_new";

  return neverActivated ? "association" : "regularization";
}

function buildMemberSnapshot(member) {
  if (!member) return null;

  return {
    idSocio: member.id_socio,
    idPlanoAtual: member.id_plano_atual,
    statusSocio: member.status_socio,
    tipoOrigem: member.tipo_origem,
    dataSolicitacao: member.data_solicitacao,
  };
}

async function lockUser(executor, userId) {
  const { rows } = await executor.query(
    `SELECT id_usuario
       FROM usuarios
      WHERE id_usuario = $1
      FOR UPDATE`,
    [userId]
  );

  return rows[0] || null;
}

async function getActivePlan(executor, planCode) {
  const { rows } = await executor.query(
    `SELECT id_plano,
            codigo_plano,
            nome,
            descricao,
            valor_mensal,
            moeda,
            percentual_desconto_loja,
            mensalidades_para_brinde,
            descricao_brinde,
            ativo
       FROM planos_associacao
      WHERE LOWER(codigo_plano) = LOWER($1)
        AND ativo = TRUE
      LIMIT 1`,
    [planCode]
  );

  return rows[0] || null;
}

async function getMemberForUpdate(executor, userId) {
  const { rows } = await executor.query(
    `SELECT id_socio,
            id_usuario,
            id_socio_legado,
            id_plano_atual,
            numero_socio,
            status_socio,
            tipo_origem,
            data_solicitacao,
            data_ativacao,
            data_inativacao,
            inativo_desde,
            created_at,
            updated_at
       FROM socios
      WHERE id_usuario = $1
      LIMIT 1
      FOR UPDATE`,
    [userId]
  );

  return rows[0] || null;
}

async function createPendingMember(executor, { userId, planId }) {
  const { rows } = await executor.query(
    `INSERT INTO socios (
       id_usuario,
       id_plano_atual,
       status_socio,
       tipo_origem,
       data_solicitacao,
       created_at,
       updated_at
     )
     VALUES ($1, $2, 'pending_validation', 'app_new', NOW(), NOW(), NOW())
     RETURNING *`,
    [userId, planId]
  );

  return rows[0];
}

async function updatePendingMember(executor, { socioId, planId }) {
  const { rows } = await executor.query(
    `UPDATE socios
        SET id_plano_atual = $2,
            status_socio = 'pending_validation',
            data_solicitacao = NOW(),
            updated_at = NOW()
      WHERE id_socio = $1
      RETURNING *`,
    [socioId, planId]
  );

  return rows[0] || null;
}

async function insertAudit(executor, {
  socioId,
  userId,
  action,
  previousValue,
  newValue,
  ip,
  userAgent,
}) {
  await executor.query(
    `INSERT INTO auditoria_socio (
       id_socio,
       acao,
       valor_anterior,
       valor_novo,
       executado_por,
       origem,
       ip,
       user_agent,
       created_at
     )
     VALUES ($1, $2, $3::jsonb, $4::jsonb, $5, 'app', $6, $7, NOW())`,
    [
      socioId,
      action,
      previousValue ? JSON.stringify(previousValue) : null,
      JSON.stringify(newValue),
      userId,
      ip || null,
      userAgent || null,
    ]
  );
}

async function requestMemberAssociation({ userId, planCode, ip = null, userAgent = null }) {
  return db.withTx(async (client) => {
    const user = await lockUser(client, userId);

    if (!user) {
      throw new MemberAssociationRequestError({
        code: "user_not_found",
        message: "Usuário não encontrado.",
        status: 404,
      });
    }

    const plan = await getActivePlan(client, planCode);

    if (!plan) {
      throw new MemberAssociationRequestError({
        code: "plan_not_found",
        message: "Plano não encontrado ou indisponível.",
        status: 404,
      });
    }

    const existingMember = await getMemberForUpdate(client, userId);

    if (existingMember?.status_socio === "active") {
      throw new MemberAssociationRequestError({
        code: "member_already_active",
        message: "Sua associação já está ativa.",
        status: 409,
      });
    }

    if (
      existingMember &&
      !REQUESTABLE_MEMBER_STATUSES.has(existingMember.status_socio)
    ) {
      throw new MemberAssociationRequestError({
        code: "member_status_not_eligible",
        message: "O estado atual da associação exige análise da Savóia.",
        status: 409,
      });
    }

    const requestType = inferRequestType(existingMember);
    const samePendingRequest = Boolean(
      existingMember &&
      existingMember.status_socio === "pending_validation" &&
      Number(existingMember.id_plano_atual) === Number(plan.id_plano)
    );

    if (samePendingRequest) {
      return {
        created: false,
        alreadyPending: true,
        requestType,
        member: existingMember,
        plan,
      };
    }

    const previousValue = buildMemberSnapshot(existingMember);
    const member = existingMember
      ? await updatePendingMember(client, {
          socioId: existingMember.id_socio,
          planId: plan.id_plano,
        })
      : await createPendingMember(client, {
          userId,
          planId: plan.id_plano,
        });

    if (!member) {
      throw new MemberAssociationRequestError({
        code: "member_request_conflict",
        message: "Não foi possível registrar a solicitação.",
        status: 409,
      });
    }

    const newValue = buildMemberSnapshot(member);

    await insertAudit(client, {
      socioId: member.id_socio,
      userId,
      action: requestType === "association"
        ? "association_requested"
        : "regularization_requested",
      previousValue,
      newValue: {
        ...newValue,
        planCode: plan.codigo_plano,
      },
      ip,
      userAgent,
    });

    return {
      created: !existingMember,
      alreadyPending: false,
      requestType,
      member,
      plan,
    };
  });
}

module.exports = {
  MemberAssociationRequestError,
  requestMemberAssociation,
};
