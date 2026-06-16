-- migrations/202606151_member_core.sql
-- Núcleo inicial de Sócios — APP Savóia
--
-- Escopo:
-- - socios_legado
-- - planos_associacao
-- - socios
-- - auditoria_socio
--
-- Fora do escopo desta migration:
-- - assinaturas
-- - cobranças
-- - métodos de pagamento
-- - fidelidade_movimentos
-- - benefícios
-- - carteirinhas

CREATE TABLE IF NOT EXISTS socios_legado (
  id_socio_legado BIGSERIAL PRIMARY KEY,
  numero_socio_legado VARCHAR(50) NOT NULL,
  nome VARCHAR(180) NOT NULL,
  cpf_normalizado VARCHAR(11),
  cpf_hash VARCHAR(128),
  email VARCHAR(180),
  telefone VARCHAR(30),
  status_legado VARCHAR(50),
  origem_importacao VARCHAR(120) DEFAULT 'planilha_legado',
  arquivo_origem VARCHAR(255),
  linha_origem INTEGER,
  dados_originais JSONB,
  importado_em TIMESTAMPTZ DEFAULT NOW(),
  vinculado_em TIMESTAMPTZ,
  id_usuario_vinculado INTEGER REFERENCES usuarios(id_usuario) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT chk_socios_legado_cpf_normalizado
    CHECK (cpf_normalizado IS NULL OR cpf_normalizado ~ '^[0-9]{11}$')
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_socios_legado_numero
  ON socios_legado (numero_socio_legado);

CREATE UNIQUE INDEX IF NOT EXISTS ux_socios_legado_cpf_normalizado
  ON socios_legado (cpf_normalizado)
  WHERE cpf_normalizado IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_socios_legado_cpf_hash
  ON socios_legado (cpf_hash)
  WHERE cpf_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_socios_legado_email
  ON socios_legado (LOWER(email))
  WHERE email IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_socios_legado_usuario_vinculado
  ON socios_legado (id_usuario_vinculado)
  WHERE id_usuario_vinculado IS NOT NULL;

CREATE TABLE IF NOT EXISTS planos_associacao (
  id_plano BIGSERIAL PRIMARY KEY,
  nome VARCHAR(120) NOT NULL,
  descricao TEXT,
  valor_mensal NUMERIC(10, 2) NOT NULL DEFAULT 0,
  moeda CHAR(3) NOT NULL DEFAULT 'BRL',
  ativo BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT chk_planos_associacao_valor_mensal
    CHECK (valor_mensal >= 0),
  CONSTRAINT chk_planos_associacao_moeda
    CHECK (moeda ~ '^[A-Z]{3}$')
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_planos_associacao_nome
  ON planos_associacao (LOWER(nome));

INSERT INTO planos_associacao (nome, descricao, valor_mensal, moeda, ativo)
SELECT
  'Mensalidade Savóia',
  'Plano inicial de mensalidade da associação Savóia.',
  35.00,
  'BRL',
  TRUE
WHERE NOT EXISTS (
  SELECT 1 FROM planos_associacao WHERE LOWER(nome) = LOWER('Mensalidade Savóia')
);

CREATE TABLE IF NOT EXISTS socios (
  id_socio BIGSERIAL PRIMARY KEY,
  id_usuario INTEGER NOT NULL REFERENCES usuarios(id_usuario) ON DELETE CASCADE,
  id_socio_legado BIGINT REFERENCES socios_legado(id_socio_legado) ON DELETE SET NULL,
  id_plano_atual BIGINT REFERENCES planos_associacao(id_plano) ON DELETE SET NULL,
  numero_socio VARCHAR(50),
  status_socio VARCHAR(30) NOT NULL DEFAULT 'inactive',
  tipo_origem VARCHAR(30) NOT NULL DEFAULT 'app_new',
  observacao TEXT,
  data_solicitacao TIMESTAMPTZ DEFAULT NOW(),
  data_ativacao TIMESTAMPTZ,
  data_inativacao TIMESTAMPTZ,
  inativo_desde TIMESTAMPTZ,
  fidelidade_preservada_ate TIMESTAMPTZ,
  validado_por INTEGER REFERENCES usuarios(id_usuario) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT chk_socios_status_socio
    CHECK (status_socio IN ('pending_validation', 'active', 'inactive', 'blocked', 'cancelled')),
  CONSTRAINT chk_socios_tipo_origem
    CHECK (tipo_origem IN ('app_new', 'legacy_import', 'manual_admin')),
  CONSTRAINT chk_socios_numero_para_legado
    CHECK (tipo_origem <> 'legacy_import' OR numero_socio IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_socios_id_usuario
  ON socios (id_usuario);

CREATE UNIQUE INDEX IF NOT EXISTS ux_socios_numero_socio
  ON socios (numero_socio)
  WHERE numero_socio IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_socios_id_socio_legado
  ON socios (id_socio_legado)
  WHERE id_socio_legado IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_socios_status_socio
  ON socios (status_socio);

CREATE INDEX IF NOT EXISTS ix_socios_tipo_origem
  ON socios (tipo_origem);

CREATE INDEX IF NOT EXISTS ix_socios_plano_atual
  ON socios (id_plano_atual)
  WHERE id_plano_atual IS NOT NULL;

CREATE TABLE IF NOT EXISTS auditoria_socio (
  id_auditoria BIGSERIAL PRIMARY KEY,
  id_socio BIGINT REFERENCES socios(id_socio) ON DELETE SET NULL,
  acao VARCHAR(80) NOT NULL,
  valor_anterior JSONB,
  valor_novo JSONB,
  executado_por INTEGER REFERENCES usuarios(id_usuario) ON DELETE SET NULL,
  origem VARCHAR(40) NOT NULL DEFAULT 'sistema',
  ip INET,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT chk_auditoria_socio_origem
    CHECK (origem IN ('sistema', 'app', 'backoffice', 'importacao', 'gateway'))
);

CREATE INDEX IF NOT EXISTS ix_auditoria_socio_id_socio
  ON auditoria_socio (id_socio);

CREATE INDEX IF NOT EXISTS ix_auditoria_socio_acao
  ON auditoria_socio (acao);

CREATE INDEX IF NOT EXISTS ix_auditoria_socio_created_at
  ON auditoria_socio (created_at DESC);

COMMENT ON TABLE socios_legado IS 'Base importada da planilha de sócios legados da Savóia.';
COMMENT ON COLUMN socios_legado.numero_socio_legado IS 'Número de sócio preservado da base/planilha legada.';
COMMENT ON COLUMN socios_legado.cpf_normalizado IS 'CPF apenas com números. Usado no MVP para conciliação automática.';
COMMENT ON COLUMN socios_legado.cpf_hash IS 'Campo reservado para lookup seguro por hash/HMAC de CPF.';

COMMENT ON TABLE socios IS 'Vínculo associativo entre usuário do app e a Savóia.';
COMMENT ON COLUMN socios.numero_socio IS 'Número de sócio usado no app/carteirinha; pode vir da base legada.';
COMMENT ON COLUMN socios.status_socio IS 'Estado associativo: pending_validation, active, inactive, blocked ou cancelled.';
COMMENT ON COLUMN socios.tipo_origem IS 'Origem do vínculo: app_new, legacy_import ou manual_admin.';
COMMENT ON COLUMN socios.fidelidade_preservada_ate IS 'Data limite para preservação da fidelidade em caso de inadimplência.';

COMMENT ON TABLE auditoria_socio IS 'Auditoria de mudanças relevantes no domínio de sócios.';
