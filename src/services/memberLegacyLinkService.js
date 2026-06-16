// src/services/memberLegacyLinkService.js
const db = require("../config/DB");

function onlyDigits(value) {
  return String(value || "").replace(/\D/g, "");
}

function normalizeCpf(cpf) {
  const normalized = onlyDigits(cpf);
  return /^\d{11}$/.test(normalized) ? normalized : null;
}

function buildPublicLinkResult({ linked, reason = null, socio = null, legado = null, alreadyLinked = false }) {
  return {
    linked,
    reason,
    alreadyLinked,
    memberStatus: linked ? "socio_inativo" : "nao_socio",
    memberNumber: socio?.numero_socio || legado?.numero_socio_legado || null,
    legacyMemberId: legado?.id_socio_legado || null,
  };
}

async function getDefaultPlanId(executor) {
  const { rows } = await executor.query(
    `SELECT id_plano
       FROM planos_associacao
      WHERE ativo = true
      ORDER BY id_plano ASC
      LIMIT 1`
  );

  return rows[0]?.id_plano || null;
}

async function findLegacyMemberByCpf(executor, cpfNormalizado) {
  const { rows } = await executor.query(
    `SELECT id_socio_legado,
            numero_socio_legado,
            nome,
            cpf_normalizado,
            email,
            telefone,
            status_legado,
            id_usuario_vinculado
       FROM socios_legado
      WHERE cpf_normalizado = $1
      LIMIT 1`,
    [cpfNormalizado]
  );

  return rows[0] || null;
}

async function findExistingMemberByUserId(executor, userId) {
  const { rows } = await executor.query(
    `SELECT *
       FROM socios
      WHERE id_usuario = $1
      LIMIT 1`,
    [userId]
  );

  return rows[0] || null;
}

async function insertAudit(executor, { socioId, action, payload }) {
  await executor.query(
    `INSERT INTO auditoria_socio (id_socio, acao, valor_novo, origem, created_at)
     VALUES ($1, $2, $3::jsonb, 'sistema', NOW())`,
    [socioId, action, JSON.stringify(payload)]
  );
}

async function createMemberFromLegacy(executor, { userId, legado, defaultPlanId }) {
  const { rows } = await executor.query(
    `INSERT INTO socios (
       id_usuario,
       id_socio_legado,
       id_plano_atual,
       numero_socio,
       status_socio,
       tipo_origem,
       observacao,
       data_solicitacao,
       inativo_desde,
       created_at,
       updated_at
     )
     VALUES ($1, $2, $3, $4, 'inactive', 'legacy_import', $5, NOW(), NOW(), NOW(), NOW())
     RETURNING *`,
    [
      userId,
      legado.id_socio_legado,
      defaultPlanId,
      legado.numero_socio_legado,
      "Vínculo automático criado por CPF a partir da base de sócios legados.",
    ]
  );

  return rows[0];
}

async function updateExistingMemberFromLegacy(executor, { existingMember, legado, defaultPlanId }) {
  const { rows } = await executor.query(
    `UPDATE socios
        SET id_socio_legado = $2,
            id_plano_atual = COALESCE(id_plano_atual, $3),
            numero_socio = COALESCE(numero_socio, $4),
            status_socio = CASE
              WHEN status_socio = 'pending_validation' THEN 'inactive'
              ELSE status_socio
            END,
            tipo_origem = CASE
              WHEN tipo_origem = 'app_new' THEN 'legacy_import'
              ELSE tipo_origem
            END,
            observacao = COALESCE(observacao, 'Vínculo automático atualizado por CPF a partir da base de sócios legados.'),
            inativo_desde = COALESCE(inativo_desde, NOW()),
            updated_at = NOW()
      WHERE id_socio = $1
        AND (id_socio_legado IS NULL OR id_socio_legado = $2)
      RETURNING *`,
    [
      existingMember.id_socio,
      legado.id_socio_legado,
      defaultPlanId,
      legado.numero_socio_legado,
    ]
  );

  return rows[0] || null;
}

async function markLegacyAsLinked(executor, { legado, userId }) {
  const { rows } = await executor.query(
    `UPDATE socios_legado
        SET id_usuario_vinculado = $2,
            vinculado_em = COALESCE(vinculado_em, NOW()),
            updated_at = NOW()
      WHERE id_socio_legado = $1
        AND (id_usuario_vinculado IS NULL OR id_usuario_vinculado = $2)
      RETURNING *`,
    [legado.id_socio_legado, userId]
  );

  return rows[0] || null;
}

async function linkLegacyMemberForUserInTx(executor, { userId, cpf }) {
  const cpfNormalizado = normalizeCpf(cpf);

  if (!userId) {
    return buildPublicLinkResult({ linked: false, reason: "missing_user_id" });
  }

  if (!cpfNormalizado) {
    return buildPublicLinkResult({ linked: false, reason: "invalid_cpf" });
  }

  const legado = await findLegacyMemberByCpf(executor, cpfNormalizado);

  if (!legado) {
    return buildPublicLinkResult({ linked: false, reason: "legacy_not_found" });
  }

  if (legado.id_usuario_vinculado && Number(legado.id_usuario_vinculado) !== Number(userId)) {
    return buildPublicLinkResult({
      linked: false,
      reason: "legacy_already_linked_to_other_user",
      legado,
    });
  }

  const existingMember = await findExistingMemberByUserId(executor, userId);

  if (existingMember?.id_socio_legado === legado.id_socio_legado) {
    await markLegacyAsLinked(executor, { legado, userId });
    return buildPublicLinkResult({
      linked: true,
      socio: existingMember,
      legado,
      alreadyLinked: true,
    });
  }

  if (existingMember?.id_socio_legado && existingMember.id_socio_legado !== legado.id_socio_legado) {
    return buildPublicLinkResult({
      linked: false,
      reason: "user_already_linked_to_other_legacy_member",
      socio: existingMember,
      legado,
    });
  }

  const defaultPlanId = await getDefaultPlanId(executor);
  const socio = existingMember
    ? await updateExistingMemberFromLegacy(executor, { existingMember, legado, defaultPlanId })
    : await createMemberFromLegacy(executor, { userId, legado, defaultPlanId });

  if (!socio) {
    return buildPublicLinkResult({
      linked: false,
      reason: "member_update_conflict",
      legado,
    });
  }

  const linkedLegacy = await markLegacyAsLinked(executor, { legado, userId });

  if (!linkedLegacy) {
    return buildPublicLinkResult({
      linked: false,
      reason: "legacy_update_conflict",
      socio,
      legado,
    });
  }

  await insertAudit(executor, {
    socioId: socio.id_socio,
    action: "legacy_member_linked",
    payload: {
      userId,
      idSocioLegado: legado.id_socio_legado,
      numeroSocioLegado: legado.numero_socio_legado,
      numeroSocio: socio.numero_socio,
      cpfMatched: true,
      statusSocio: socio.status_socio,
      tipoOrigem: socio.tipo_origem,
    },
  });

  return buildPublicLinkResult({ linked: true, socio, legado });
}

async function linkLegacyMemberForUser({ userId, cpf }) {
  return db.withTx((client) => linkLegacyMemberForUserInTx(client, { userId, cpf }));
}

module.exports = {
  linkLegacyMemberForUser,
  linkLegacyMemberForUserInTx,
  normalizeCpf,
};
