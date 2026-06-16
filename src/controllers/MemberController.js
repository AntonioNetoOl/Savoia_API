// src/controllers/MemberController.js
const db = require("../config/DB");

function getUserIdFromToken(req) {
  return req.user?.id || req.user?.id_usuario || req.user?.sub || req.usuario?.id || req.usuario?.id_usuario || req.usuario?.sub;
}

function normalizeMemberStatus(status) {
  const normalized = String(status || "").trim().toLowerCase();

  if (["socio_ativo", "ativo", "atualizado", "adimplente", "active"].includes(normalized)) {
    return "socio_ativo";
  }

  if (
    [
      "socio_inativo",
      "inativo",
      "pendente_verificacao",
      "pendente",
      "inadimplente",
      "inactive",
      "pending_validation",
      "blocked",
      "cancelled",
    ].includes(normalized)
  ) {
    return "socio_inativo";
  }

  return "nao_socio";
}

function getStatusContent(memberStatus, user) {
  const hasLegacyLink = user.tipo_origem === "legacy_import";

  const contentByStatus = {
    nao_socio: {
      title: "Você ainda não é sócio",
      description: "Associe-se para acessar benefícios, carteirinha e programa de fidelidade.",
      actionLabel: "Conhecer associação",
    },
    socio_inativo: {
      title: hasLegacyLink ? "Sócio legado vinculado" : "Associação inativa",
      description: hasLegacyLink
        ? "Encontramos seu cadastro na base da Savóia. Sua associação está inativa até atualização ou regularização pela sede."
        : "Sua associação está inativa. Regularize para acessar benefícios de sócio ativo.",
      actionLabel: hasLegacyLink ? "Acompanhar associação" : "Regularizar associação",
    },
    socio_ativo: {
      title: "Sócio ativo",
      description: "Sua associação está ativa. Acompanhe fidelidade, benefícios e pagamentos.",
      actionLabel: "Ver detalhes",
    },
  };

  return contentByStatus[memberStatus] || contentByStatus.nao_socio;
}

function buildMemberSummary(user) {
  const rawStatus = user.status_socio || user.status;
  const memberStatus = normalizeMemberStatus(rawStatus);
  const statusContent = getStatusContent(memberStatus, user);
  const isActiveMember = memberStatus === "socio_ativo";
  const isInactiveMember = memberStatus === "socio_inativo";
  const hasAssociation = Boolean(user.id_socio);
  const hasLegacyLink = user.tipo_origem === "legacy_import";
  const memberNumber = user.numero_socio || user.numero_socio_legado || null;

  return {
    user: {
      id: user.id_usuario,
      name: user.nome,
      email: user.email,
    },
    memberStatus,
    statusCard: statusContent,
    association: {
      title: isActiveMember
        ? "Associação ativa"
        : isInactiveMember
          ? hasLegacyLink
            ? "Sócio legado vinculado"
            : "Associação inativa"
          : "Não associado",
      description: isActiveMember
        ? "Sua associação está ativa na base Savóia."
        : isInactiveMember
          ? hasLegacyLink
            ? "Seu número de sócio foi encontrado na base legada. A sede poderá atualizar plano, situação e fidelidade quando necessário."
            : "Sua associação está inativa no momento."
          : "Você ainda não possui uma associação vinculada à sua conta.",
      memberNumber,
      since: user.data_ativacao ? String(new Date(user.data_ativacao).getFullYear()) : null,
      origin: user.tipo_origem || null,
      linked: hasAssociation,
    },
    loyalty: {
      title: "Fidelidade Savóia",
      description: isActiveMember
        ? "Progresso temporário baseado em mensalidades pagas pelo app."
        : hasLegacyLink
          ? "A fidelidade de sócios legados será atualizada pela sede/backoffice ou por pagamentos realizados no app."
          : "A fidelidade será liberada após ativação da associação.",
      paidInstallments: isActiveMember ? 2 : 0,
      requiredInstallments: 12,
      nextBenefitLabel: "Item grátis na loja",
    },
    payments: {
      title: "Pagamentos",
      description: "Acompanhe histórico, próximos lançamentos e cartões cadastrados.",
      nextChargeLabel: isActiveMember ? "Abril/2026" : null,
      recurrenceEnabled: isActiveMember,
    },
    benefits: {
      title: "Benefícios",
      description: isActiveMember
        ? "Benefícios disponíveis e futuros serão exibidos nesta área."
        : "Benefícios de sócio ativo ficam disponíveis após ativação ou regularização da associação.",
      availableCount: isActiveMember ? 1 : 0,
    },
  };
}

async function getMemberSummary(req, res, next) {
  try {
    const userId = getUserIdFromToken(req);

    if (!userId) {
      return res.status(401).json({ erro: "Usuário não identificado no token." });
    }

    const { rows } = await db.query(
      `SELECT u.id_usuario,
              u.nome,
              u.email,
              u.status,
              s.id_socio,
              s.numero_socio,
              s.status_socio,
              s.tipo_origem,
              s.data_solicitacao,
              s.data_ativacao,
              s.data_inativacao,
              s.inativo_desde,
              s.fidelidade_preservada_ate,
              sl.id_socio_legado,
              sl.numero_socio_legado,
              sl.status_legado
         FROM usuarios u
         LEFT JOIN socios s ON s.id_usuario = u.id_usuario
         LEFT JOIN socios_legado sl ON sl.id_socio_legado = s.id_socio_legado
        WHERE u.id_usuario = $1
        LIMIT 1`,
      [userId]
    );

    const user = rows[0];

    if (!user) {
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }

    return res.json(buildMemberSummary(user));
  } catch (error) {
    next(error);
  }
}

module.exports = {
  getMemberSummary,
};
