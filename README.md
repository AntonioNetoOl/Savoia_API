# Savóia API

API REST do ecossistema Savóia, responsável por autenticação, usuários, regras do domínio de associados, integrações do aplicativo e persistência em PostgreSQL.

O aplicativo mobile que consome esta API está em:

`AntonioNetoOl/Sav-ia-APP`

## Stack

- Node.js
- Express
- PostgreSQL
- `pg`
- JWT
- bcrypt
- Joi
- Nodemailer
- dotenv

## Responsabilidades atuais

- cadastro e autenticação de usuários;
- geração e validação de JWT;
- recuperação de acesso por código;
- integração de e-mail via SMTP;
- área e regras de associação de sócios;
- vínculo com registros legados de associados;
- informações de menu consumidas pelo aplicativo;
- pagamentos, fidelidade e benefícios em evolução;
- migrations SQL versionadas;
- documentação de domínio e modelagem.

## Estrutura principal

```text
src/
├── config/        configuração de banco
├── controllers/   controllers HTTP
├── middlewares/   autenticação e tratamento de erros
├── routes/        definição de rotas
├── services/      regras e serviços de domínio
├── utils/         e-mail e utilitários
└── validators/    validações de entrada

migrations/        migrations SQL e scripts de rollback
docs/domain/       decisões, fluxos, ERD e modelagem do domínio
scripts/           execução de migrations
```

## Configuração

Crie seu arquivo local `.env` a partir de `.env.example` e ajuste as variáveis conforme seu ambiente.

Variáveis principais:

```text
PORT
CORS_ORIGIN
DB_HOST
DB_PORT
DB_NAME
DB_USER
DB_PASS
JWT_SECRET
SMTP_HOST
SMTP_PORT
SMTP_USER
SMTP_PASS
```

Nenhuma credencial real deve ser versionada no repositório.

## Executar localmente

### Instalar dependências

```bash
npm install
```

### Executar migrations

```bash
npm run migrate
```

Também existem scripts específicos para os conjuntos de migrations de associados, pagamentos e fidelidade.

### Desenvolvimento

```bash
npm run dev
```

### Execução padrão

```bash
npm start
```

Por padrão, a aplicação utiliza a porta `4000` quando `PORT` não é informada.

## Banco de dados

A camada de persistência utiliza PostgreSQL com pool de conexões e suporte a transações explícitas.

As migrations do domínio de associados estão versionadas em `migrations/`, incluindo scripts de aplicação e rollback.

## Documentação de domínio

A pasta `docs/domain/` reúne documentação técnica sobre:

- segurança e tratamento de CPF;
- decisões de negócio para associados;
- modelagem das entidades;
- fluxos do domínio;
- ERD;
- pagamentos e recorrência;
- fidelidade e benefícios;
- futura carteirinha digital.

## Segurança

O projeto utiliza hash de senha, autenticação por JWT e configuração sensível via variáveis de ambiente. Para ambientes reais, utilize um `JWT_SECRET` forte, restrinja o `CORS_ORIGIN` e nunca versione credenciais ou segredos.

## Status

Projeto em desenvolvimento contínuo, com foco atual na evolução do domínio de associados e sua integração com o aplicativo Savóia.
