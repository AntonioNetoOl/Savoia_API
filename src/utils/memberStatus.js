function getMemberStatus({ id_socio, status_socio }) {
  if (!id_socio) return "nao_socio";
  return status_socio === "active" ? "socio_ativo" : "socio_inativo";
}

module.exports = getMemberStatus;
