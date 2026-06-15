// src/controllers/MemberController.js
const db = require("../config/DB");

function getUserIdFromToken(req) {
  return req.user?.id || req.user?.id_usuario || req.user?.sub || req.usuario?.id || req.usuario?.id_usuario || req.usuario?.sub;
}

function normalizeMemberStatus(status) {
  const normalized = String(status || "").trim().toLowerCase();

  if (["socio_ativo", "ativo", "atualizado", "adimplente"].includes(normalized)) {
    return "socio_ativo";
  }

  if (["socio_inativo", "inativo", "pendente_verificacao", "pendente", "inadimplente"].includes(normalized)) {
    return "socio_inativo";
  }

  return "nao_socio";
}

function getStatusContent(memberStatus) {
  const contentByStatus = {
    nao_socio: {
      title: "Você ainda não é sócio",
      description: "Associe-se para acessar benefícios, carteirinha e programa de fidelidade.",
      actionLabel: "Conhecer associação",
    },
    socio_inativo: {
      title: "Associação em validação",
      description: "Seu cadastro de sócio está reservado para validação pela Savóia.",
      actionLabel: "Acompanhar validação",
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
  const memberStatus = normalizeMemberStatus(user.status);
  const statusContent = getStatusContent(memberStatus);
  const isActiveMember = memberStatus === "socio_ativo";
  const isInactiveMember = memberStatus === "socio_inativo";

  return {
    user: {
      id: user.id_usuario,
      name: user.nome,
      email: user.email,
    },
    memberStatus,
    statusCard: statusContent,
    association: {
      title: isActiveMember ? "Associação ativa" : isInactiveMember ? "Validação pendente" : "Não associado",
      description: isActiveMember
        ? "Sua associação está ativa na base Savóia."
        : isInactiveMember
          ? "A sede/backoffice deverá validar a ativação da sua associação."
          : "Você ainda não possui uma associação ativa vinculada à sua conta.",
      memberNumber: isActiveMember ? `SAV-${String(user.id_usuario).padStart(5, "0")}` : null,
      since: isActiveMember ? "2026" : null,
    },
    loyalty: {
      title: "Fidelidade Savóia",
      description: isActiveMember
        ? "Progresso temporário baseado em mensalidades pagas pelo app."
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
        : "Benefícios serão exibidos após ativação da associação.",
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
      `SELECT id_usuario, nome, email, status
         FROM usuarios
        WHERE id_usuario = $1
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
