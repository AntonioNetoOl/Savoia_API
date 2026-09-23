# Savóia API

API REST do ecossistema Savóia, responsável por autenticação, usuários, domínio de associados, integrações do aplicativo e persistência em PostgreSQL.

O aplicativo mobile que consome esta API está em `AntonioNetoOl/Sav-ia-APP`.

## Visão do domínio de sócios

A conta de acesso e o vínculo associativo são conceitos diferentes:

```text
usuarios = conta/login no aplicativo
socios   = vínculo associativo com a Savóia
```

Um usuário pode existir sem ser sócio. Quando existe vínculo, `socios.id_usuario` é único: cada usuário pode ter no máximo um registro em `socios`.

O aplicativo apresenta três estados:

| Estado visual | Significado |
|---|---|
| `nao_socio` | O usuário não possui registro em `socios` |
| `socio_inativo` | Existe vínculo, mas o estado interno não é `active` |
| `socio_ativo` | O estado interno do vínculo é `active` |

Valores como `legacy_import` descrevem a origem interna do vínculo e não são estados visuais.

O estado da conta em `usuarios.status` é independente do estado associativo e não deve ser usado para decidir se alguém é sócio.

## Stack

- Node.js;
- Express;
- PostgreSQL e `pg`;
- JWT;
- bcrypt;
- Joi;
- Nodemailer;
- dotenv.

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
docs/domain/       domínio, fluxos, DER, fidelidade e brindes
scripts/           execução de migrations
```

## Configuração

Crie o arquivo local `.env` a partir de `.env.example` e ajuste as variáveis conforme o ambiente:

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

```bash
npm install
npm run dev
```

Para a execução padrão:

```bash
npm start
```

Por padrão, a aplicação utiliza a porta `4000` quando `PORT` não é informada.

Antes de iniciar contra um banco ainda não preparado, execute as migrations na ordem:

```bash
npm run migrate:member-core
npm run migrate:member-finance-loyalty
```

O comando genérico de migration exige o caminho de um arquivo SQL. Os atalhos e rollbacks disponíveis estão documentados em [`migrations/README.md`](migrations/README.md).

## Testes de autenticação, estados associativos e calendário

Com Node.js 22 e as dependências do lockfile instaladas (`npm ci`), execute `npm test`.
O executor nativo testa o middleware e os controllers de login, validação do código de recuperação e redefinição, com JWT e bcrypt reais e dados sintéticos. Não lê `.env`, não envia e-mail e bloqueia conexões PostgreSQL; o driver é simulado. Isso não valida banco, SMTP ou integração HTTP reais.

Tokens de login existentes, sem `kind`, continuam válidos. Tokens `kind: "pwdreset"` são recusados pelo middleware das rotas comuns com HTTP 401; continuam aceitos exclusivamente no fluxo de redefinição, conforme as verificações já existentes.

O mesmo comando executa `test/member-status.test.js`: testa as respostas dos controllers de resumo e menu para ausência de vínculo e todos os estados associativos, independentemente do status da conta e da origem. Verifica também erros de consulta, identificação obrigatória e a recusa de solicitação para vínculo bloqueado. O driver PostgreSQL é simulado; esses testes não comprovam locks, transações ou persistência real da solicitação.

O comando também executa `test/member-billing-calendar.test.js`, com datas explícitas e sem mocks: verifica meses curtos, anos bissextos, tolerância e reativação. Para rodar somente esses cálculos, use `node --test test/member-billing-calendar.test.js`. As funções ainda não são chamadas pelos endpoints nem por tarefas agendadas; não cobram, não enviam avisos e não mudam status. Consulte a [interface do calendário](docs/domain/socios-fluxos.md#interface-do-calendário-implementada).

## Testes de transações do cadastro

Execute `npm run test:registration` com PostgreSQL 18 instalado. No Windows, os executáveis são procurados em `C:/Program Files/PostgreSQL/18/bin`; para outro caminho, use `npm run test:registration -- "caminho/para/bin"`.

O comando cria e encerra uma instância descartável, com diretório temporário, porta livre em localhost e credenciais efêmeras. Antes de criar tabelas, confere o diretório reportado pelo servidor. Não lê `.env` nem utiliza o banco de desenvolvimento. A estrutura das três tabelas de cadastro em `test/fixtures/registration-schema.sql` foi exportada sem dados do ambiente de desenvolvimento; é uma fixture de teste, não uma migration. A migration core existente é aplicada apenas nessa instância para exercitar o vínculo legado.

Os testes usam PostgreSQL real, inclusive falhas provocadas e concorrência. O pool recicla conexões a cada empréstimo para detectar transações incorretas por `pool.query`; nenhuma query é simulada. SMTP é simulado e logs de cadastro são silenciados para não expor códigos. A instância e seus arquivos são removidos ao terminar. `npm test` executa os testes de JWT, estados associativos e calendário, sem precisar iniciar PostgreSQL.

O envio de cadastro confirma sessão e código na mesma transação antes de tentar e-mail. A confirmação grava usuário e consumo de código/sessão na mesma transação; o vínculo legado é tentado após o commit. Falhas de SMTP ou de vínculo legado não desfazem esses commits. Esta correção não muda as políticas de cooldown ou consumo concorrente de OTP.

## Endpoints do domínio de sócios

Os endpoints abaixo exigem autenticação:

| Método | Endpoint | Responsabilidade |
|---|---|---|
| `GET` | `/api/member/summary` | Retorna o estado visual do usuário e o resumo disponível de associação, plano, fidelidade, cobranças, recorrência, benefícios e brinde |
| `GET` | `/api/member/plans` | Lista os planos de associação ativos |
| `POST` | `/api/member/association-request` | Registra uma solicitação de associação ou regularização a partir de `planCode` |

O `POST /api/member/association-request` cria ou reutiliza o único registro em `socios`, mantém a solicitação em `pending_validation` e grava auditoria quando há mudança. Ele não cria assinatura ou cobrança, não processa pagamento e não ativa o sócio automaticamente.

Detalhes de estados, respostas e fluxos estão em [`docs/domain/socios-fluxos.md`](docs/domain/socios-fluxos.md).

## Planos atuais

O catálogo abaixo ainda expõe o modelo anterior de fidelidade. A direção aprovada passa a ser pontuação por mensalidade paga, com regras a definir. Vencimentos, tolerância e reativação estão documentados em [regras aprovadas de mensalidades](docs/domain/socios-fluxos.md#mensalidades-regras-aprovadas-integração-pendente); as automações financeiras continuam pendentes.

| Plano | Mensalidade | Desconto nas lojas | Fidelidade |
|---|---:|---:|---|
| Mutley | R$ 30,00 | 10% | Brinde após 12 mensalidades consecutivas pagas |
| Dick | R$ 50,00 | 15% | Brinde após 12 mensalidades consecutivas pagas |
| Vigarista | R$ 75,00 | 20% | Brinde após 12 mensalidades consecutivas pagas |

O brinde é retirado presencialmente na sede e está sujeito à disponibilidade de estoque. Benefícios gerais do sócio não são a mesma coisa que o brinde de fidelidade.

## Banco e estágio atual

As migrations já criam a estrutura de associação, planos, auditoria, métodos de pagamento, assinaturas, cobranças, fidelidade e brindes. A existência dessas tabelas não significa que o fluxo financeiro completo esteja implementado.

Continuam fora do escopo atual:

- gateway e checkout reais;
- carteirinha digital e QR Code;
- backoffice;
- controle real de estoque;
- cupom online;
- automação de inadimplência;
- automação de zeragem de fidelidade.

## Documentação

- [Domínio, estados, endpoints e fluxos de sócios](docs/domain/socios-fluxos.md)
- [DER do domínio de sócios](docs/domain/der-socios.md)
- [Benefícios e brindes de fidelidade](docs/domain/beneficios-fidelidade.md)
- [Execução e escopo das migrations](migrations/README.md)

As migrations são a fonte de verdade para o schema. O runtime é a fonte de verdade para os comportamentos já implementados.

## Segurança

O projeto utiliza hash de senha, autenticação por JWT e configuração sensível via variáveis de ambiente. Em ambientes reais, use um `JWT_SECRET` forte, restrinja `CORS_ORIGIN` e nunca versione credenciais ou segredos.

## Desenvolvimento com Codex

- [Instruções para agentes](AGENTS.md)
- [Harness de engenharia](docs/engineering/harness-engenharia.md)
- [Adoção de Ponytail, skills e TDD](docs/engineering/adocao-codex.md)
