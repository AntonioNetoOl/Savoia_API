-- migrations/202606162_member_finance_loyalty.down.sql
-- Rollback da estrutura de pagamentos, recorrência e fidelidade.
-- Atenção: remove tabelas e dados criados nessas tabelas.

DROP TABLE IF EXISTS brindes_fidelidade_socio;
DROP TABLE IF EXISTS fidelidade_movimentos;
DROP TABLE IF EXISTS cobrancas;
DROP TABLE IF EXISTS assinaturas;
DROP TABLE IF EXISTS metodos_pagamento;

UPDATE planos_associacao
   SET ativo = TRUE,
       updated_at = NOW()
 WHERE LOWER(nome) = LOWER('Mensalidade Savóia');

DROP INDEX IF EXISTS ux_planos_associacao_codigo_plano;

ALTER TABLE planos_associacao
  DROP CONSTRAINT IF EXISTS chk_planos_associacao_percentual_desconto_loja;

ALTER TABLE planos_associacao
  DROP CONSTRAINT IF EXISTS chk_planos_associacao_mensalidades_para_brinde;

ALTER TABLE planos_associacao
  DROP COLUMN IF EXISTS descricao_brinde,
  DROP COLUMN IF EXISTS mensalidades_para_brinde,
  DROP COLUMN IF EXISTS percentual_desconto_loja,
  DROP COLUMN IF EXISTS codigo_plano;
