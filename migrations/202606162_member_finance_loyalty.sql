-- migrations/202606162_member_finance_loyalty.sql
-- Estrutura de pagamentos, recorrência e fidelidade — APP Savóia
--
-- Escopo:
-- - complementos em planos_associacao
-- - seed dos planos Mutley, Dick e Vigarista
-- - metodos_pagamento
-- - assinaturas
-- - cobrancas
-- - fidelidade_movimentos
-- - brindes_fidelidade_socio
--
-- Fora do escopo desta migration:
-- - carteirinhas
-- - cupom/código para loja online
-- - controle de estoque real
-- - importação de planilha
-- - sistema de gerenciamento/backoffice

ALTER TABLE planos_associacao
  ADD COLUMN IF NOT EXISTS codigo_plano VARCHAR(40),
  ADD COLUMN IF NOT EXISTS percentual_desconto_loja NUMERIC(5, 2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS mensalidades_para_brinde INTEGER NOT NULL DEFAULT 12,
  ADD COLUMN IF NOT EXISTS descricao_brinde TEXT;

ALTER TABLE planos_associacao
  DROP CONSTRAINT IF EXISTS chk_planos_associacao_percentual_desconto_loja;

ALTER TABLE planos_associacao
  ADD CONSTRAINT chk_planos_associacao_percentual_desconto_loja
    CHECK (percentual_desconto_loja >= 0 AND percentual_desconto_loja <= 100);

ALTER TABLE planos_associacao
  DROP CONSTRAINT IF EXISTS chk_planos_associacao_mensalidades_para_brinde;

ALTER TABLE planos_associacao
  ADD CONSTRAINT chk_planos_associacao_mensalidades_para_brinde
    CHECK (mensalidades_para_brinde > 0);

CREATE UNIQUE INDEX IF NOT EXISTS ux_planos_associacao_codigo_plano
  ON planos_associacao (codigo_plano)
  WHERE codigo_plano IS NOT NULL;

UPDATE planos_associacao
   SET ativo = FALSE,
       updated_at = NOW()
 WHERE LOWER(nome) = LOWER('Mensalidade Savóia')
   AND codigo_plano IS NULL;

INSERT INTO planos_associacao (
  codigo_plano,
  nome,
  descricao,
  valor_mensal,
  moeda,
  ativo,
  percentual_desconto_loja,
  mensalidades_para_brinde,
  descricao_brinde,
  created_at,
  updated_at
)
SELECT
  'mutley',
  'Plano Mutley',
  'Plano mensal com 10% de desconto nas lojas da torcida e brinde de fidelidade após 12 mensalidades consecutivas pagas.',
  30.00,
  'BRL',
  TRUE,
  10.00,
  12,
  '1 Boné ou Pescador ou Touca, sujeito à disponibilidade em estoque na sede.',
  NOW(),
  NOW()
WHERE NOT EXISTS (
  SELECT 1 FROM planos_associacao WHERE codigo_plano = 'mutley' OR LOWER(nome) = LOWER('Plano Mutley')
);

INSERT INTO planos_associacao (
  codigo_plano,
  nome,
  descricao,
  valor_mensal,
  moeda,
  ativo,
  percentual_desconto_loja,
  mensalidades_para_brinde,
  descricao_brinde,
  created_at,
  updated_at
)
SELECT
  'dick',
  'Plano Dick',
  'Plano mensal com 15% de desconto nas lojas da torcida e brinde de fidelidade após 12 mensalidades consecutivas pagas.',
  50.00,
  'BRL',
  TRUE,
  15.00,
  12,
  '1 Camiseta ou Regata ou Bermuda, sujeito à disponibilidade em estoque na sede.',
  NOW(),
  NOW()
WHERE NOT EXISTS (
  SELECT 1 FROM planos_associacao WHERE codigo_plano = 'dick' OR LOWER(nome) = LOWER('Plano Dick')
);

INSERT INTO planos_associacao (
  codigo_plano,
  nome,
  descricao,
  valor_mensal,
  moeda,
  ativo,
  percentual_desconto_loja,
  mensalidades_para_brinde,
  descricao_brinde,
  created_at,
  updated_at
)
SELECT
  'vigarista',
  'Plano Vigarista',
  'Plano mensal com 20% de desconto nas lojas da torcida e brinde de fidelidade após 12 mensalidades consecutivas pagas.',
  75.00,
  'BRL',
  TRUE,
  20.00,
  12,
  '1 Agasalho ou Calça, sujeito à disponibilidade em estoque na sede.',
  NOW(),
  NOW()
WHERE NOT EXISTS (
  SELECT 1 FROM planos_associacao WHERE codigo_plano = 'vigarista' OR LOWER(nome) = LOWER('Plano Vigarista')
);

CREATE TABLE IF NOT EXISTS metodos_pagamento (
  id_metodo_pagamento BIGSERIAL PRIMARY KEY,
  id_usuario INTEGER NOT NULL REFERENCES usuarios(id_usuario) ON DELETE CASCADE,
  gateway_payment_method_id VARCHAR(160),
  brand VARCHAR(40),
  last4 CHAR(4),
  expiration_month CHAR(2),
  expiration_year CHAR(4),
  is_default BOOLEAN NOT NULL DEFAULT FALSE,
  status VARCHAR(30) NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT chk_metodos_pagamento_status
    CHECK (status IN ('active', 'expired', 'removed', 'invalid')),
  CONSTRAINT chk_metodos_pagamento_last4
    CHECK (last4 IS NULL OR last4 ~ '^[0-9]{4}$'),
  CONSTRAINT chk_metodos_pagamento_expiration_month
    CHECK (expiration_month IS NULL OR expiration_month ~ '^(0[1-9]|1[0-2])$'),
  CONSTRAINT chk_metodos_pagamento_expiration_year
    CHECK (expiration_year IS NULL OR expiration_year ~ '^[0-9]{4}$')
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_metodos_pagamento_gateway_id
  ON metodos_pagamento (gateway_payment_method_id)
  WHERE gateway_payment_method_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_metodos_pagamento_default_por_usuario
  ON metodos_pagamento (id_usuario)
  WHERE is_default = TRUE AND status = 'active';

CREATE INDEX IF NOT EXISTS ix_metodos_pagamento_usuario
  ON metodos_pagamento (id_usuario);

CREATE TABLE IF NOT EXISTS assinaturas (
  id_assinatura BIGSERIAL PRIMARY KEY,
  id_socio BIGINT NOT NULL REFERENCES socios(id_socio) ON DELETE CASCADE,
  id_plano BIGINT NOT NULL REFERENCES planos_associacao(id_plano) ON DELETE RESTRICT,
  id_metodo_pagamento BIGINT REFERENCES metodos_pagamento(id_metodo_pagamento) ON DELETE SET NULL,
  status_assinatura VARCHAR(30) NOT NULL DEFAULT 'pending',
  data_inicio TIMESTAMPTZ,
  data_cancelamento TIMESTAMPTZ,
  proxima_cobranca_em DATE,
  gateway_customer_id VARCHAR(160),
  gateway_subscription_id VARCHAR(160),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT chk_assinaturas_status
    CHECK (status_assinatura IN ('pending', 'active', 'paused', 'cancelled', 'failed'))
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_assinaturas_gateway_subscription_id
  ON assinaturas (gateway_subscription_id)
  WHERE gateway_subscription_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_assinaturas_socio_corrente
  ON assinaturas (id_socio)
  WHERE status_assinatura IN ('pending', 'active', 'paused', 'failed');

CREATE INDEX IF NOT EXISTS ix_assinaturas_socio
  ON assinaturas (id_socio);

CREATE INDEX IF NOT EXISTS ix_assinaturas_plano
  ON assinaturas (id_plano);

CREATE TABLE IF NOT EXISTS cobrancas (
  id_cobranca BIGSERIAL PRIMARY KEY,
  id_socio BIGINT NOT NULL REFERENCES socios(id_socio) ON DELETE CASCADE,
  id_assinatura BIGINT REFERENCES assinaturas(id_assinatura) ON DELETE SET NULL,
  competencia DATE NOT NULL,
  valor NUMERIC(10, 2) NOT NULL,
  moeda CHAR(3) NOT NULL DEFAULT 'BRL',
  status_cobranca VARCHAR(30) NOT NULL DEFAULT 'scheduled',
  scheduled_at TIMESTAMPTZ,
  due_at DATE NOT NULL,
  tolerance_until DATE,
  loyalty_preserved_until DATE,
  paid_at TIMESTAMPTZ,
  failed_at TIMESTAMPTZ,
  cancelled_at TIMESTAMPTZ,
  gateway_invoice_id VARCHAR(160),
  gateway_payment_id VARCHAR(160),
  origem VARCHAR(40) NOT NULL DEFAULT 'app',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT chk_cobrancas_valor
    CHECK (valor >= 0),
  CONSTRAINT chk_cobrancas_moeda
    CHECK (moeda ~ '^[A-Z]{3}$'),
  CONSTRAINT chk_cobrancas_status
    CHECK (status_cobranca IN ('scheduled', 'pending', 'paid', 'failed', 'cancelled', 'refunded')),
  CONSTRAINT chk_cobrancas_tolerance_until
    CHECK (tolerance_until IS NULL OR tolerance_until >= due_at),
  CONSTRAINT chk_cobrancas_loyalty_preserved_until
    CHECK (loyalty_preserved_until IS NULL OR loyalty_preserved_until >= due_at),
  CONSTRAINT chk_cobrancas_origem
    CHECK (origem IN ('app', 'gateway', 'manual', 'importacao'))
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_cobrancas_gateway_invoice_id
  ON cobrancas (gateway_invoice_id)
  WHERE gateway_invoice_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_cobrancas_gateway_payment_id
  ON cobrancas (gateway_payment_id)
  WHERE gateway_payment_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_cobrancas_socio
  ON cobrancas (id_socio);

CREATE INDEX IF NOT EXISTS ix_cobrancas_assinatura
  ON cobrancas (id_assinatura)
  WHERE id_assinatura IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_cobrancas_status_due
  ON cobrancas (status_cobranca, due_at);

CREATE INDEX IF NOT EXISTS ix_cobrancas_competencia
  ON cobrancas (competencia);

CREATE TABLE IF NOT EXISTS fidelidade_movimentos (
  id_movimento BIGSERIAL PRIMARY KEY,
  id_socio BIGINT NOT NULL REFERENCES socios(id_socio) ON DELETE CASCADE,
  id_cobranca BIGINT REFERENCES cobrancas(id_cobranca) ON DELETE SET NULL,
  tipo_movimento VARCHAR(40) NOT NULL,
  quantidade INTEGER NOT NULL DEFAULT 0,
  competencia DATE,
  observacao TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT chk_fidelidade_movimentos_tipo
    CHECK (tipo_movimento IN ('payment_counted', 'payment_reversed', 'manual_adjustment', 'legacy_adjustment', 'benefit_redeemed', 'loyalty_reset')),
  CONSTRAINT chk_fidelidade_movimentos_quantidade
    CHECK (quantidade >= -120 AND quantidade <= 120)
);

CREATE INDEX IF NOT EXISTS ix_fidelidade_movimentos_socio
  ON fidelidade_movimentos (id_socio, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_fidelidade_movimentos_cobranca
  ON fidelidade_movimentos (id_cobranca)
  WHERE id_cobranca IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_fidelidade_movimentos_tipo
  ON fidelidade_movimentos (tipo_movimento);

CREATE TABLE IF NOT EXISTS brindes_fidelidade_socio (
  id_brinde_socio BIGSERIAL PRIMARY KEY,
  id_socio BIGINT NOT NULL REFERENCES socios(id_socio) ON DELETE CASCADE,
  id_plano BIGINT REFERENCES planos_associacao(id_plano) ON DELETE SET NULL,
  ciclo_inicio_em DATE,
  ciclo_fim_em DATE,
  mensalidades_exigidas INTEGER NOT NULL DEFAULT 12,
  descricao_brinde TEXT NOT NULL,
  status_brinde VARCHAR(30) NOT NULL DEFAULT 'available',
  disponivel_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resgatado_em TIMESTAMPTZ,
  cancelado_em TIMESTAMPTZ,
  expira_em TIMESTAMPTZ,
  observacao TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT chk_brindes_fidelidade_status
    CHECK (status_brinde IN ('available', 'redeemed', 'cancelled', 'expired')),
  CONSTRAINT chk_brindes_fidelidade_mensalidades
    CHECK (mensalidades_exigidas > 0),
  CONSTRAINT chk_brindes_fidelidade_ciclo
    CHECK (ciclo_fim_em IS NULL OR ciclo_inicio_em IS NULL OR ciclo_fim_em >= ciclo_inicio_em)
);

CREATE INDEX IF NOT EXISTS ix_brindes_fidelidade_socio
  ON brindes_fidelidade_socio (id_socio, status_brinde);

CREATE INDEX IF NOT EXISTS ix_brindes_fidelidade_plano
  ON brindes_fidelidade_socio (id_plano)
  WHERE id_plano IS NOT NULL;

COMMENT ON COLUMN planos_associacao.codigo_plano IS 'Código interno do plano, como mutley, dick ou vigarista.';
COMMENT ON COLUMN planos_associacao.percentual_desconto_loja IS 'Percentual de desconto nas lojas da torcida para sócio em dia.';
COMMENT ON COLUMN planos_associacao.mensalidades_para_brinde IS 'Quantidade de mensalidades consecutivas pagas necessárias para liberar brinde.';
COMMENT ON COLUMN planos_associacao.descricao_brinde IS 'Descrição do brinde de fidelidade do plano, sujeito à disponibilidade em estoque.';

COMMENT ON TABLE metodos_pagamento IS 'Métodos de pagamento tokenizados no gateway; não armazenar número completo nem CVV.';
COMMENT ON TABLE assinaturas IS 'Assinaturas/recorrências associadas aos sócios.';
COMMENT ON TABLE cobrancas IS 'Cobranças mensais, lançamentos futuros, pagamentos, falhas e janelas de inadimplência/fidelidade.';
COMMENT ON TABLE fidelidade_movimentos IS 'Ledger de movimentos de fidelidade, incluindo pagamentos contados, reversões, ajustes e zeragens.';
COMMENT ON TABLE brindes_fidelidade_socio IS 'Brindes de fidelidade liberados após 12 mensalidades consecutivas pagas, com resgate presencial na sede.';
