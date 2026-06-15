// src/controllers/MenuController.js
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

async function getMe(req, res, next) {
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

    return res.json({
      id: user.id_usuario,
      name: user.nome,
      email: user.email,
      memberStatus: normalizeMemberStatus(user.status),
    });
  } catch (error) {
    next(error);
  }
}

async function getPayments(_req, res, next) {
  try {
    return res.json([
      {
        id: "pay_1",
        title: "Mensalidade Savóia",
        amount: 35,
        currency: "BRL",
        status: "confirmed",
        paidAt: "2026-02-10",
        methodLabel: "Cartão final 1234",
        competenceLabel: "Fevereiro/2026",
        source: "app",
      },
      {
        id: "pay_2",
        title: "Mensalidade Savóia",
        amount: 35,
        currency: "BRL",
        status: "pending",
        paidAt: null,
        methodLabel: "Cartão final 1234",
        competenceLabel: "Março/2026",
        source: "app",
      },
    ]);
  } catch (error) {
    next(error);
  }
}

async function getPaymentCards(_req, res, next) {
  try {
    return res.json([
      {
        id: "card_1",
        brand: "Visa",
        last4: "1234",
        expirationMonth: "08",
        expirationYear: "2028",
        isDefault: true,
      },
    ]);
  } catch (error) {
    next(error);
  }
}

async function getBenefits(_req, res, next) {
  try {
    return res.json([
      {
        id: "benefit_1",
        title: "Item grátis na loja",
        status: "available",
        description: "Benefício liberado após 12 mensalidades pagas.",
      },
    ]);
  } catch (error) {
    next(error);
  }
}

module.exports = {
  getMe,
  getPayments,
  getPaymentCards,
  getBenefits,
};
