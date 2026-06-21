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

function toNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function formatCurrency(value, currency = "BRL") {
  const amount = toNumber(value, 0);

  if (currency === "BRL") {
    return `R$ ${amount.toFixed(2).replace(".", ",")}`;
  }

  return `${currency} ${amount.toFixed(2)}`;
}

function getStatusContent(memberStatus) {
  const contentByStatus = {
    nao_socio: {
      title: "Você ainda não é sócio",
      description: "Associe-se para acessar benefícios, carteirinha e programa de fidelidade.",
      actionLabel: "Conhecer associação",
    },
    socio_inativo: {
      title: "Associação inativa",
      description: "Sua associação está inativa no momento. Regularize para acessar benefícios de sócio ativo.",
      actionLabel: "Regularizar associação",
    },
    socio_ativo: {
      title: "Sócio ativo",
      description: "Sua associação está ativa. Acompanhe plano, fidelidade, benefícios e pagamentos.",
      actionLabel: "Ver detalhes",
    },
  };

  return contentByStatus[memberStatus] || contentByStatus.nao_socio;
}

function getActiveCharge(charges) {
  return charges.find((charge) => ["scheduled", "pending"].includes(charge.status_cobranca)) || null;
}

function getLatestCharge(charges) {
  return charges[0] || null;
}

function getActiveGift(gifts) {
  return gifts.find((gift) => gift.status_brinde === "available") || null;
}

function buildPlanSummary(user) {
  if (!user.id_plano_atual) {
    return null;
  }

  return {
    id: user.id_plano_atual,
    code: user.codigo_plano,
    name: user.plano_nome,
    description: user.plano_descricao,
    monthlyAmount: toNumber(user.valor_mensal, 0),
    monthlyAmountLabel: formatCurrency(user.valor_mensal, user.moeda || "BRL"),
    currency: user.moeda || "BRL",
    storeDiscountPercent: toNumber(user.percentual_desconto_loja, 0),
    requiredInstallmentsForGift: Number(user.mensalidades_para_brinde || 12),
    giftDescription: user.descricao_brinde || null,
  };
}

function buildAvailablePlanSummary(plan) {
  return {
    id: plan.id_plano,
    code: plan.codigo_plano,
    name: plan.nome,
    description: plan.descricao || null,
    monthlyAmount: toNumber(plan.valor_mensal, 0),
    monthlyAmountLabel: formatCurrency(plan.valor_mensal, plan.moeda || "BRL"),
    currency: plan.moeda || "BRL",
    storeDiscountPercent: toNumber(plan.percentual_desconto_loja, 0),
    requiredInstallmentsForGift: Number(plan.mensalidades_para_brinde || 12),
    giftDescription: plan.descricao_brinde || null,
    active: Boolean(plan.ativo),
  };
}

function buildMemberSummary({ user, charges, loyalty, gifts }) {
  const rawStatus = user.status_socio || user.status;
  const memberStatus = normalizeMemberStatus(rawStatus);
  const statusContent = getStatusContent(memberStatus);
  const isActiveMember = memberStatus === "socio_ativo";
  const isInactiveMember = memberStatus === "socio_inativo";
  const hasAssociation = Boolean(user.id_socio);
  const memberNumber = user.numero_socio || user.numero_socio_legado || null;
  const plan = buildPlanSummary(user);
  const requiredInstallments = plan?.requiredInstallmentsForGift || 12;
  const paidInstallments = clamp(toNumber(loyalty.currentBalance, 0), 0, requiredInstallments);
  const progressPercent = requiredInstallments > 0
    ? Math.round((paidInstallments / requiredInstallments) * 100)
    : 0;
  const activeGift = getActiveGift(gifts);
  const activeCharge = getActiveCharge(charges);
  const latestCharge = getLatestCharge(charges);

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
          ? "Associação inativa"
          : "Não associado",
      description: isActiveMember
        ? "Sua associação está ativa na base Savóia."
        : isInactiveMember
          ? "Sua associação está inativa no momento. Regularize para voltar a acessar benefícios de sócio ativo."
          : "Você ainda não possui uma associação vinculada à sua conta.",
      memberNumber,
      since: user.data_ativacao ? String(new Date(user.data_ativacao).getFullYear()) : null,
      linked: hasAssociation,
    },
    plan,
    loyalty: {
      title: "Fidelidade Savóia",
      description: activeGift
        ? "Você possui um brinde de fidelidade disponível para retirada na sede, sujeito à disponibilidade de estoque."
        : plan?.giftDescription
          ? `Pague ${requiredInstallments} mensalidades consecutivas para liberar: ${plan.giftDescription}`
          : "A fidelidade será calculada a partir das mensalidades pagas pelo app.",
      paidInstallments,
      requiredInstallments,
      progressPercent,
      currentBalance: loyalty.currentBalance,
      totalCounted: loyalty.totalCounted,
      totalReversed: loyalty.totalReversed,
      totalRedeemed: loyalty.totalRedeemed,
      totalReset: loyalty.totalReset,
      nextGiftLabel: plan?.giftDescription || null,
      giftAvailable: Boolean(activeGift),
    },
    payments: {
      title: "Pagamentos",
      description: "Acompanhe histórico, próximos lançamentos e cartões cadastrados.",
      nextChargeLabel: activeCharge?.competencia_label || activeCharge?.competencia || null,
      nextChargeDueAt: activeCharge?.due_at || null,
      latestStatus: latestCharge?.status_cobranca || null,
      recurrenceEnabled: Boolean(user.id_assinatura && user.status_assinatura === "active"),
      subscriptionStatus: user.status_assinatura || null,
    },
    benefits: {
      title: "Benefícios",
      description: isActiveMember
        ? plan?.storeDiscountPercent
          ? `${plan.storeDiscountPercent}% de desconto nas lojas da torcida para sócio em dia.`
          : "Benefícios de sócio em dia serão exibidos nesta área."
        : "Benefícios de sócio ativo ficam disponíveis após ativação ou regularização da associação.",
      availableCount: activeGift ? 1 : 0,
      storeDiscountPercent: plan?.storeDiscountPercent || 0,
      gift: activeGift
        ? {
            id: activeGift.id_brinde_socio,
            status: activeGift.status_brinde,
            description: activeGift.descricao_brinde,
            availableAt: activeGift.disponivel_em,
            expiresAt: activeGift.expira_em,
            redemptionType: "presencial_sede",
            stockNotice: "Sujeito à disponibilidade em estoque.",
          }
        : null,
    },
  };
}

async function getMemberBase(userId) {
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
            sl.status_legado,
            p.id_plano AS id_plano_atual,
            p.codigo_plano,
            p.nome AS plano_nome,
            p.descricao AS plano_descricao,
            p.valor_mensal,
            p.moeda,
            p.percentual_desconto_loja,
            p.mensalidades_para_brinde,
            p.descricao_brinde,
            a.id_assinatura,
            a.status_assinatura,
            a.proxima_cobranca_em
       FROM usuarios u
       LEFT JOIN socios s ON s.id_usuario = u.id_usuario
       LEFT JOIN socios_legado sl ON sl.id_socio_legado = s.id_socio_legado
       LEFT JOIN planos_associacao p ON p.id_plano = s.id_plano_atual
       LEFT JOIN assinaturas a ON a.id_socio = s.id_socio
        AND a.status_assinatura IN ('pending', 'active', 'paused', 'failed')
      WHERE u.id_usuario = $1
      LIMIT 1`,
    [userId]
  );

  return rows[0] || null;
}

async function getRecentCharges(socioId) {
  if (!socioId) return [];

  const { rows } = await db.query(
    `SELECT id_cobranca,
            status_cobranca,
            competencia,
            TO_CHAR(competencia, 'MM/YYYY') AS competencia_label,
            valor,
            moeda,
            due_at,
            tolerance_until,
            loyalty_preserved_until,
            paid_at,
            failed_at,
            cancelled_at
       FROM cobrancas
      WHERE id_socio = $1
      ORDER BY due_at DESC, id_cobranca DESC
      LIMIT 6`,
    [socioId]
  );

  return rows;
}

async function getLoyaltySummary(socioId) {
  if (!socioId) {
    return {
      currentBalance: 0,
      totalCounted: 0,
      totalReversed: 0,
      totalRedeemed: 0,
      totalReset: 0,
    };
  }

  const { rows } = await db.query(
    `SELECT COALESCE(SUM(quantidade), 0)::int AS current_balance,
            COALESCE(SUM(CASE WHEN tipo_movimento = 'payment_counted' THEN quantidade ELSE 0 END), 0)::int AS total_counted,
            COALESCE(SUM(CASE WHEN tipo_movimento = 'payment_reversed' THEN ABS(quantidade) ELSE 0 END), 0)::int AS total_reversed,
            COALESCE(SUM(CASE WHEN tipo_movimento = 'benefit_redeemed' THEN ABS(quantidade) ELSE 0 END), 0)::int AS total_redeemed,
            COALESCE(SUM(CASE WHEN tipo_movimento = 'loyalty_reset' THEN ABS(quantidade) ELSE 0 END), 0)::int AS total_reset
       FROM fidelidade_movimentos
      WHERE id_socio = $1`,
    [socioId]
  );

  const row = rows[0] || {};

  return {
    currentBalance: Number(row.current_balance || 0),
    totalCounted: Number(row.total_counted || 0),
    totalReversed: Number(row.total_reversed || 0),
    totalRedeemed: Number(row.total_redeemed || 0),
    totalReset: Number(row.total_reset || 0),
  };
}

async function getAvailableGifts(socioId) {
  if (!socioId) return [];

  const { rows } = await db.query(
    `SELECT id_brinde_socio,
            id_plano,
            descricao_brinde,
            status_brinde,
            disponivel_em,
            resgatado_em,
            cancelado_em,
            expira_em
       FROM brindes_fidelidade_socio
      WHERE id_socio = $1
      ORDER BY disponivel_em DESC, id_brinde_socio DESC
      LIMIT 5`,
    [socioId]
  );

  return rows;
}

async function getMemberSummary(req, res, next) {
  try {
    const userId = getUserIdFromToken(req);

    if (!userId) {
      return res.status(401).json({ erro: "Usuário não identificado no token." });
    }

    const user = await getMemberBase(userId);

    if (!user) {
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }

    const [charges, loyalty, gifts] = await Promise.all([
      getRecentCharges(user.id_socio),
      getLoyaltySummary(user.id_socio),
      getAvailableGifts(user.id_socio),
    ]);

    return res.json(buildMemberSummary({ user, charges, loyalty, gifts }));
  } catch (error) {
    next(error);
  }
}

async function getMemberPlans(_req, res, next) {
  try {
    const { rows } = await db.query(
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
        WHERE ativo = TRUE
          AND codigo_plano IS NOT NULL
        ORDER BY valor_mensal ASC, id_plano ASC`
    );

    return res.json({
      plans: rows.map(buildAvailablePlanSummary),
    });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  getMemberSummary,
  getMemberPlans,
};