# Instruções para agentes — Savóia API

## Antes de trabalhar

Leia o [harness de engenharia](docs/engineering/harness-engenharia.md) e o código do fluxo afetado. Use [savoia-backend-change](.agents/skills/savoia-backend-change/SKILL.md) para mudanças ou revisões do backend. Para instalação de ferramentas, consulte o [guia de adoção](docs/engineering/adocao-codex.md).

Respeite o tipo de pedido: explicar/revisar/diagnosticar não autoriza implementar. Não faça refatoração transversal em uma tarefa pontual.

## Organização existente

Node.js/Express com CommonJS, PostgreSQL via `pg`, Joi e JWT. Reutilize `src/routes/`, `controllers/`, `services/`, `validators/` e `middlewares/`; não introduza ORM ou migração de linguagem por convenção de uma skill.

`src/config/DB.js` fornece `query` e `withTx`. Para transações, use o mesmo client fornecido por `withTx` em todas as queries. Não use `pool.query` entre BEGIN e COMMIT.

## Invariantes de domínio

- Usuário é conta; sócio é vínculo. Um usuário pode não ser sócio e pode ter no máximo um registro em `socios`.
- Estados visuais: `nao_socio`, `socio_inativo`, `socio_ativo`. `legacy_import` é origem, não estado visual. `usuarios.status` não substitui o estado do vínculo.
- GET `/api/member/summary`, GET `/api/member/plans` e POST `/api/member/association-request` são contratos existentes.
- A solicitação recebe `planCode`, cria/reutiliza o vínculo em `pending_validation` e distingue associação de regularização. Repetição do mesmo plano pendente é idempotente; não duplica vínculo nem auditoria de mudança inexistente.
- Não transforma sócio ativo/bloqueado em pendente para contornar elegibilidade. Preserve as respostas e verificações existentes.
- Solicitação não cria assinatura/cobrança, não processa pagamento e não ativa o sócio. Estrutura financeira no banco não significa fluxo financeiro implementado.
- Benefício geral não é brinde de fidelidade. Leia as regras vigentes em [benefícios e fidelidade](docs/domain/beneficios-fidelidade.md), sem duplicar o catálogo em código.

Consulte [fluxos e contratos](docs/domain/socios-fluxos.md), [DER](docs/domain/der-socios.md) e [migrations](migrations/README.md). Schema físico vem das migrations; comportamento existente vem do runtime. Divergências com regras aprovadas devem ser relatadas, não normalizadas silenciosamente.

## Verificação e limites

Confirme os scripts no `package.json`. Há `start`, `dev`, atalhos de migrations, `test` (JWT e estados associativos com driver simulado, mais cálculos puros do calendário de mensalidades) e `test:registration` (cadastro com PostgreSQL 18 descartável); ainda não há script de lint. Consulte o README antes dos testes de banco: eles criam uma instância própria e não usam `.env` ou o banco de desenvolvimento. Não invente resultados de testes. `node --check caminho.js` só verifica sintaxe, não comportamento.

Não execute migrations/rollback como verificação rotineira. As migrations de sócios pressupõem tabelas preexistentes; consulte o README delas antes de preparar banco de teste. Novas migrations só em tarefa que as inclua; preserve migrations históricas aplicadas.

Para comportamento novo/correção, use TDD quando houver infraestrutura e interface de teste acordadas. Se faltar, informe a lacuna e proponha o mínimo necessário. Documentação requer revisão de links, não implantação de suíte.

## Code Review Rules

- Sinalize perda de autenticação/autorização, finalidade inadequada de tokens, dados sensíveis em logs ou queries não parametrizadas.
- Sinalize quebra de vínculo único, idempotência, elegibilidade, atomicidade ou auditoria na solicitação.
- Verifique se falhas abortam a transação e se a concorrência continua protegida.
- Não aprove ativação/cobrança implícita nem confusão entre origem e estado visual.
- Revise o diff inteiro, inclusive arquivos novos e mudanças não commitadas. Simplificação não deve remover proteções.
