// src/validators/memberValidator.js
const Joi = require("joi");

const associationRequestSchema = Joi.object({
  planCode: Joi.string()
    .trim()
    .lowercase()
    .pattern(/^[a-z0-9][a-z0-9_-]{0,49}$/)
    .required(),
}).required();

function validateAssociationRequest(payload) {
  const { value, error } = associationRequestSchema.validate(payload || {}, {
    abortEarly: false,
    allowUnknown: false,
    stripUnknown: false,
  });

  if (!error) {
    return { ok: true, value, errors: [] };
  }

  return {
    ok: false,
    value: null,
    errors: error.details.map((detail) => ({
      field: detail.path.join("."),
      type: detail.type,
      message: detail.message,
    })),
  };
}

module.exports = {
  associationRequestSchema,
  validateAssociationRequest,
};
