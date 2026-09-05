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
npm run migrate
npm run dev
```

Para a execução padrão:

```bash
npm start
```

Por padrão, a aplicação utiliza a porta `4000` quando `PORT` não é informada.

O comando genérico de migration recebe o caminho de um arquivo SQL. Os atalhos e rollbacks disponíveis estão documentados em [`migrations/README.md`](migrations/README.md).

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

