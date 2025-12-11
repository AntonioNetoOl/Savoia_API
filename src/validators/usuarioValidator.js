// src/validators/usuarioValidator.js
const Joi = require("joi");

const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const schemaCadastro = Joi.object({
  nome: Joi.string().min(3).max(120).required(),
  cpf: Joi.string().pattern(/^\d{11}$/).required(), 
  email: Joi.string().email().required(),
  senha: Joi.string().min(6).required(),
  numero: Joi.string().allow("", null),
});

const schemaLogin = Joi.object({
  identificador: Joi.string().required(),
  senha: Joi.string().min(6).required(),
});

function isValidEmail(email) {
  return emailRe.test(String(email || "").toLowerCase());
}
function onlyDigits(s = "") {
  return String(s).replace(/\D+/g, "");
}

function validateCadastro({ nome, cpf, email, senha, numero }) {
  const errors = {};
  if (!nome || String(nome).trim().length < 3) errors.nome = "Nome inválido";
  const cpfDigits = onlyDigits(cpf);
  if (cpfDigits.length !== 11) errors.cpf = "CPF inválido";
  if (!isValidEmail(email)) errors.email = "E-mail inválido";
  if (!senha || String(senha).length < 6) errors.senha = "Senha curta";
  const phone = onlyDigits(numero);
  if (phone.length < 10) errors.numero = "Telefone inválido";
  return { ok: Object.keys(errors).length === 0, errors, cpf: cpfDigits, numero: phone };
}

module.exports = {
  schemaCadastro,
  schemaLogin,
  isValidEmail,
  onlyDigits,
  validateCadastro,
};
