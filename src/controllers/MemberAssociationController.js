// src/controllers/MemberAssociationController.js
const {
  MemberAssociationRequestError,
  requestMemberAssociation,
} = require("../services/memberAssociationRequestService");
const {
  validateAssociationRequest,
} = require("../validators/memberValidator");

function getUserIdFromToken(req) {
  return req.user?.id ||
    req.user?.id_usuario ||
    req.user?.sub ||
    req.usuario?.id ||
    req.usuario?.id_usuario ||
    req.usuario?.sub;
}

function normalizeRequestIp(value) {
  const ip = String(value || "")
    .trim()
    .replace(/^::ffff:/, "");

  if (!ip || ip.length > 64 || !/^[0-9a-fA-F:.]+$/.test(ip)) {
    return null;
  }

  return ip;
}

function getRequestUserAgent(req) {
  const userAgent = String(req.headers?.["user-agent"] || "").trim();
  return userAgent ? userAgent.slice(0, 500) : null;
}

async function createAssociationRequest(req, res, next) {
  try {
    const userId = getUserIdFromToken(req);

    if (!userId) {
      return res.status(401).json({
        erro: "Usuário não identificado no token.",
        code: "missing_user_id",
      });
    }

    const validation = validateAssociationRequest(req.body);

    if (!validation.ok) {
      return res.status(400).json({
        erro: "Dados inválidos.",
        code: "invalid_request",
        detalhes: validation.errors.map(({ field, type }) => ({ field, type })),
      });
    }

    const result = await requestMemberAssociation({
      userId,
      planCode: validation.value.planCode,
      ip: normalizeRequestIp(req.ip || req.socket?.remoteAddress),
      userAgent: getRequestUserAgent(req),
    });

    return res.status(result.created ? 201 : 200).json({
      request: {
        type: result.requestType,
        status: "pending",
        alreadyPending: result.alreadyPending,
        planCode: result.plan.codigo_plano,
        planName: result.plan.nome,
        requestedAt: result.member.data_solicitacao,
      },
      memberStatus: "socio_inativo",
    });
  } catch (error) {
    if (error instanceof MemberAssociationRequestError) {
      return res.status(error.status).json({
        erro: error.message,
        code: error.code,
      });
    }

    next(error);
  }
}

module.exports = {
  createAssociationRequest,
};
