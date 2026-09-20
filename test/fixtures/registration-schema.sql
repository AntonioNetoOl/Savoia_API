-- Estrutura de desenvolvimento PostgreSQL 18, consultada em 19/09/2026; sem dados.
-- Fixture de teste, não migration de produção.
CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;
CREATE TYPE public.user_status AS ENUM ('PENDENTE_VERIFICACAO', 'PROCESSANDO_CONFIRMACAO', 'ATIVO', 'NAO_ENCONTRADO', 'INATIVO');
CREATE OR REPLACE FUNCTION public.set_data_alteracao()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
BEGIN
  -- atualiza o carimbo de alteração no momento do UPDATE
  NEW.dataalteracao := CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$function$

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

CREATE TABLE public.sessoes_cadastro (
    id uuid DEFAULT gen_random_uuid() CONSTRAINT sessaocadastro_id_not_null NOT NULL,
    nome text CONSTRAINT sessaocadastro_nome_not_null NOT NULL,
    cpf character varying(11) CONSTRAINT sessaocadastro_cpf_not_null NOT NULL,
    email public.citext CONSTRAINT sessaocadastro_email_not_null NOT NULL,
    senha_hash text CONSTRAINT sessaocadastro_senha_hash_not_null NOT NULL,
    numero character varying(20) CONSTRAINT sessaocadastro_numero_not_null NOT NULL,
    usado boolean DEFAULT false CONSTRAINT sessaocadastro_usado_not_null NOT NULL,
    criado_em timestamp with time zone DEFAULT now() CONSTRAINT sessaocadastro_criado_em_not_null NOT NULL,
    payload_json jsonb
);

CREATE TABLE public.usuarios (
    id_usuario integer CONSTRAINT usuario_iid_not_null NOT NULL,
    nome character varying(120) CONSTRAINT usuario_nome_not_null NOT NULL,
    cpf character varying(14) CONSTRAINT usuario_cpf_not_null NOT NULL,
    email public.citext CONSTRAINT usuario_email_not_null NOT NULL,
    senha_hash text CONSTRAINT usuario_senha_hash_not_null NOT NULL,
    numero character varying(20),
    status public.user_status DEFAULT 'PENDENTE_VERIFICACAO'::public.user_status CONSTRAINT usuario_status_not_null NOT NULL,
    datacriacao timestamp without time zone DEFAULT CURRENT_TIMESTAMP CONSTRAINT usuario_created_at_not_null NOT NULL,
    dataalteracao timestamp with time zone DEFAULT now() CONSTRAINT usuario_updated_at_not_null NOT NULL,
    origem_cadastro character varying(50) DEFAULT 'APP'::character varying,
    verificado_em timestamp without time zone,
    email_verificado boolean DEFAULT false NOT NULL
);

CREATE SEQUENCE public.usuario_iid_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.usuario_iid_seq OWNED BY public.usuarios.id_usuario;

CREATE TABLE public.verificacoes_email (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    id_usuario integer,
    email public.citext,
    tipo text NOT NULL,
    codigo character varying(6) NOT NULL,
    expira_em timestamp with time zone NOT NULL,
    usado boolean DEFAULT false NOT NULL,
    tentativas smallint DEFAULT 0 NOT NULL,
    ip inet,
    user_agent text,
    criado_em timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_email_ou_usuario CHECK (((email IS NOT NULL) OR (id_usuario IS NOT NULL)))
);

ALTER TABLE ONLY public.usuarios ALTER COLUMN id_usuario SET DEFAULT nextval('public.usuario_iid_seq'::regclass);

ALTER TABLE ONLY public.sessoes_cadastro
    ADD CONSTRAINT sessaocadastro_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.usuarios
    ADD CONSTRAINT usuario_cpf_key UNIQUE (cpf);

ALTER TABLE ONLY public.usuarios
    ADD CONSTRAINT usuario_email_key UNIQUE (email);

ALTER TABLE ONLY public.usuarios
    ADD CONSTRAINT usuario_pkey PRIMARY KEY (id_usuario);

ALTER TABLE ONLY public.verificacoes_email
    ADD CONSTRAINT verificacoes_email_pkey PRIMARY KEY (id);

CREATE INDEX idx_sess_email_criado_desc ON public.sessoes_cadastro USING btree (email, criado_em DESC);

CREATE INDEX idx_sessaocadastro_cpf ON public.sessoes_cadastro USING btree (cpf);

CREATE INDEX idx_sessaocadastro_email ON public.sessoes_cadastro USING btree (email);

CREATE INDEX idx_sessoes_email ON public.sessoes_cadastro USING btree (lower((email)::text));

CREATE INDEX idx_usuario_cpf ON public.usuarios USING btree (cpf);

CREATE INDEX idx_usuario_email ON public.usuarios USING btree (email);

CREATE UNIQUE INDEX idx_usuarios_email_unique_trim ON public.usuarios USING btree (lower(TRIM(BOTH FROM email)));

CREATE INDEX idx_verif_email_ativos ON public.verificacoes_email USING btree (email, tipo, expira_em) WHERE (usado = false);

CREATE UNIQUE INDEX ux_usuarios_cpf ON public.usuarios USING btree (cpf);

CREATE UNIQUE INDEX ux_usuarios_email ON public.usuarios USING btree (email);

CREATE TRIGGER trg_usuarios_data_alteracao BEFORE UPDATE ON public.usuarios FOR EACH ROW EXECUTE FUNCTION public.set_data_alteracao();

ALTER TABLE ONLY public.verificacoes_email
    ADD CONSTRAINT verificacoes_email_id_usuario_fkey FOREIGN KEY (id_usuario) REFERENCES public.usuarios(id_usuario) ON DELETE CASCADE;
