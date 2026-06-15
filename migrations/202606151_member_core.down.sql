-- migrations/202606151_member_core.down.sql
-- Rollback da migration inicial do núcleo de Sócios.
-- Atenção: remove tabelas e dados criados pela migration.

DROP TABLE IF EXISTS auditoria_socio;
DROP TABLE IF EXISTS socios;
DROP TABLE IF EXISTS planos_associacao;
DROP TABLE IF EXISTS socios_legado;
