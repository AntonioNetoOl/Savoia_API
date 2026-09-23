# Domínio, estados e fluxos de sócios

Este documento descreve a arquitetura e os comportamentos atualmente implementados no domínio de sócios. As migrations são a fonte de verdade para o schema; o runtime é a fonte de verdade para os fluxos disponíveis.

## Regra central

Usuário e sócio são entidades diferentes:

```text
usuarios = conta que acessa o aplicativo
socios   = vínculo associativo com a Savóia
```

Um usuário pode existir sem vínculo associativo. O índice único `ux_socios_id_usuario` garante que cada usuário tenha no máximo um registro em `socios`.

Mudança de plano, regularização e mudança de status atualizam esse mesmo registro; não criam um segundo sócio para o usuário.

## Estados do banco e do aplicativo

O banco aceita os seguintes valores em `socios.status_socio`:

```text
pending_validation
active
inactive
blocked
cancelled
```

O contrato do domínio apresenta ao aplicativo três estados visuais:

| Situação | Estado visual |
|---|---|
| Não existe registro em `socios` | `nao_socio` |
| `status_socio = active` | `socio_ativo` |
| `pending_validation`, `inactive`, `blocked` ou `cancelled` | `socio_inativo` |

`app_new`, `legacy_import` e `manual_admin` são valores internos de `tipo_origem`. Eles explicam como o vínculo surgiu e não devem ser usados como rótulo visual principal.

`usuarios.status` representa o estado da conta. A existência e o estado da associação devem ser derivados de `socios`, sem misturar os dois conceitos.

### Ponto de consistência no runtime

`GET /api/member/summary` e `GET /api/me` usam o mesmo mapeamento: sem `socios.id_socio`, retornam `nao_socio`; com vínculo, somente `active` retorna `socio_ativo`, e os demais estados retornam `socio_inativo`. O status da conta e a origem do vínculo não participam dessa classificação. A apresentação de `blocked` como inativo não altera sua inelegibilidade para solicitar associação.

## Endpoints implementados

Todos os endpoints abaixo exigem autenticação.

### `GET /api/member/summary`

Retorna uma visão agregada do usuário autenticado, incluindo:

- estado visual do vínculo;
- número e situação da associação;
- plano atual, quando houver;
- resumo da fidelidade;
- cobranças existentes;
- estado da recorrência;
- desconto do plano;
- brinde disponível, quando houver.

O endpoint consulta dados existentes. Ele não cria cobrança, não processa pagamento e não executa as automações financeiras pendentes.

### `GET /api/member/plans`

Lista os planos ativos de `planos_associacao`, ordenados por valor. A resposta inclui código, nome, mensalidade, desconto, regra de fidelidade e descrição do brinde.

Os códigos atuais são `mutley`, `dick` e `vigarista`.

### `POST /api/member/association-request`

Recebe um corpo JSON com o código do plano:

```json
{
  "planCode": "mutley"
}
```

O fluxo atual:

1. identifica o usuário pelo token;
2. valida o corpo e rejeita campos desconhecidos;
3. inicia uma transação e bloqueia o usuário para evitar solicitações concorrentes;
4. valida se o plano existe e está ativo;
5. bloqueia e consulta o registro existente em `socios`, quando houver;
6. cria o registro ou reutiliza o único registro do usuário;
7. define o plano escolhido e `status_socio = pending_validation`;
8. classifica a solicitação como `association` ou `regularization`;
9. grava `association_requested` ou `regularization_requested` em `auditoria_socio` quando há mudança.

Uma repetição da mesma solicitação já pendente reaproveita o registro sem duplicá-lo. Um sócio `active` ou um estado não elegível recebe conflito em vez de ser sobrescrito.

A resposta visual é `socio_inativo`, pois `pending_validation` é um estado interno ainda não ativo.

Este endpoint não:

- cria `assinaturas`;
- cria `cobrancas`;
- cadastra método de pagamento;
- processa pagamento;
- ativa automaticamente o sócio.

## Vínculo com a base legada

Após a criação de um usuário, o backend tenta localizar um registro em `socios_legado` pelo CPF normalizado.

Quando encontra um registro disponível para o mesmo usuário, o serviço cria ou atualiza o único registro em `socios`, preserva o número legado, registra `tipo_origem = legacy_import`, mantém o vínculo interno como `inactive` e grava o evento `legacy_member_linked`.

Para o app, esse resultado continua sendo `socio_inativo`. `legacy_import` identifica a origem do vínculo, não o estado apresentado ao usuário.

## Mensalidades: regras aprovadas, integração pendente

As decisões abaixo foram aprovadas em setembro de 2026. São o contrato para a evolução financeira; não descrevem automações já disponíveis. O endpoint de solicitação continua sem cobrar ou ativar associação.

- A primeira mensalidade confirmada ativa a associação e define o dia original dos vencimentos mensais. Selecionar plano ou retornar da página de pagamento não comprova pagamento.
- O vencimento é mensal, não a cada 30 dias. Quando o mês não comportar o dia original, usa-se seu último dia; nos meses seguintes retorna-se ao dia original. Exemplo: 31/01/2028 → 29/02/2028 → 31/03/2028 → 30/04/2028.
- Datas de negócio seguem `America/Sao_Paulo`. O dia do vencimento não conta como atraso. Uma renovação não paga preserva a associação ativa nos sete dias seguintes; a inativação ocorre no início do oitavo dia.
- Exemplo: vencimento 10/05, lembretes de 11 a 17/05, inativação às 00:00 de 18/05. Pagamento até 17/05 mantém o próximo vencimento em 10/06.
- Reativação após esse prazo exige somente uma mensalidade, sem quitar meses anteriores, e inicia novo ciclo na data efetiva do pagamento. Isso não autoriza desbloquear vínculo `blocked` nem ignorar restrições da conta.
- Recorrência é opcional e exige consentimento. Uma tentativa automática recusada permite pagamento manual e segue a mesma tolerância. Cobrança manual e automática devem ser coordenadas para evitar duplicidade.
- Durante o atraso, enviar no máximo um lembrete no aplicativo e um por e-mail em cada dia de 1 a 7. Interromper após confirmação do pagamento. Notificações e agendamento ainda não estão implementados.
- Foto poderá ser enviada depois da ativação, pelo fluxo da carteirinha. Troca de plano de sócio ativo fica para outra etapa.
- Cada mensalidade paga poderá gerar pontuação para brindes; quantidade, expiração, resgate e reversões ainda serão modelados. Não implementar contagem consecutiva ou zeragem como regra nova.

### Interface do calendário implementada

[`src/utils/memberBillingCalendar.js`](../../src/utils/memberBillingCalendar.js) fornece funções puras em CommonJS, sem dependências adicionais. Não está conectado aos endpoints ou a tarefas agendadas e não acessa banco, gateway, relógio ou notificações.

| Função | Entrada | Resultado |
|---|---|---|
| `getMonthlyDueDate(anchorDate, monthOffset)` | Data original do ciclo e número inteiro positivo de meses desde essa data | Vencimento ajustado ao mês, preservando o dia original |
| `getGracePeriod(dueDate)` | Vencimento da renovação | `firstReminderDate`, `lastReminderDate` e `inactiveDate` |
| `getNextCycle({ anchorDate, dueDate, paymentDate })` | Data original, vencimento pertencente ao ciclo e data efetiva de um pagamento confirmado | `anchorDate`, `nextDueDate` e `restartsCycle` |

Todas as datas são strings `AAAA-MM-DD`, anos 0001–9999, já interpretadas no calendário de `America/Sao_Paulo`. UTC é usado internamente apenas para aritmética de datas, sem depender do fuso da máquina. O chamador futuro deve converter timestamps do provedor para a data local; `inactiveDate` representa o início desse dia local, não meia-noite UTC.

Para a primeira mensalidade, a data de pagamento inicia o ciclo; `getMonthlyDueDate(paymentDate, 1)` fornece o próximo vencimento. Nas renovações, deve-se preservar `anchorDate`, não substituí-la pelo vencimento ajustado de fevereiro. `getNextCycle` recebe o vencimento em aberto que iniciou o atraso, não um vencimento posterior inventado, e reinicia o calendário somente quando o pagamento ocorre a partir de `inactiveDate`.

Entradas inválidas e vencimentos incompatíveis com o ciclo geram `RangeError`. Pagamentos antecipados ainda não foram modelados e são recusados por `getNextCycle`; isso é um limite desta interface, não uma nova proibição no aplicativo. O cálculo não verifica pagamento, autorização, bloqueio ou duplicidade e não executa reativação. Essas verificações pertencem à futura integração; `restartsCycle` indica apenas o resultado de calendário.

Exemplos reproduzíveis em [`test/member-billing-calendar.test.js`](../../test/member-billing-calendar.test.js): vencimento em 10/05/2026, pagamento em 15/05 mantém 10/06; pagamento em 20/05 inicia ciclo com vencimento em 20/06. Notificações e inativação automática permanecem pendentes.

### Segurança e decisões ainda abertas

PagBank é candidato, sem integração ou produto contratado confirmado. A conta informada é PF. Confirmar APIs habilitadas, notificações, consulta de pagamentos e recorrência antes de definir o fluxo; recorrência no débito não está garantida. Ver [restrição da API de recorrência para PF](https://faq.pagbank.com.br/duvida/clientes-pessoa-fisica-pf-podem-integrar-via-api-de-pagamento-recorrente/3417).

A futura integração exige idempotência, autenticação de notificações conforme o provedor, tratamento de eventos duplicados/fora de ordem, reconciliação e confirmação de valor, moeda e mensalidade no servidor. Usar a data efetiva do pagamento confirmada pelo provedor, não a chegada do webhook, para avaliar o prazo. Não armazenar número completo de cartão ou CVV; credenciais e referências sensíveis não podem aparecer em logs.

Ainda é necessário definir estornos/contestações e validar como encerrar tentativas antigas na reativação. Não confundir inativação associativa com cancelamento de cobrança no provedor. Falhas de notificação não devem gerar novas cobranças nem modificar o pagamento.

## Planos e fidelidade: modelo anterior ainda exposto

A tabela abaixo descreve o catálogo e o contrato atuais. A regra de 12 mensalidades consecutivas foi substituída na direção aprovada por pontuação ainda a definir. Schema, dados e textos do aplicativo não foram migrados nesta etapa; não tratar o modelo anterior como especificação para novas automações.

| Plano | Mensalidade | Desconto | Liberação do brinde |
|---|---:|---:|---|
| Mutley | R$ 30,00 | 10% | Após 12 mensalidades consecutivas pagas |
| Dick | R$ 50,00 | 15% | Após 12 mensalidades consecutivas pagas |
| Vigarista | R$ 75,00 | 20% | Após 12 mensalidades consecutivas pagas |

O brinde é retirado presencialmente na sede e depende da disponibilidade de estoque. Benefícios gerais do sócio ativo e brindes de fidelidade são conceitos distintos.

As regras e os limites atuais estão detalhados em [Benefícios e brindes de fidelidade](./beneficios-fidelidade.md).

## Estrutura financeira

As tabelas `metodos_pagamento`, `assinaturas`, `cobrancas`, `fidelidade_movimentos` e `brindes_fidelidade_socio` já existem. Elas preservam o modelo e os relacionamentos necessários para a evolução financeira.

O fluxo financeiro completo ainda não está implementado. A presença das tabelas não deve ser interpretada como disponibilidade de gateway, checkout, cobrança recorrente automática ou concessão automática de fidelidade.

## Fora do escopo atual

- gateway e checkout reais;
- carteirinha digital;
- QR Code;
- backoffice;
- controle real de estoque;
- cupom online;
- automação de inadimplência;
- automação de zeragem de fidelidade.

Esses itens só devem ser documentados como implementados depois que existirem no runtime e, quando aplicável, nas migrations.

## Referências

- [DER do domínio de sócios](./der-socios.md)
- [Benefícios e brindes de fidelidade](./beneficios-fidelidade.md)
- [Execução e escopo das migrations](../../migrations/README.md)

