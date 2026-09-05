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

A API os apresenta ao aplicativo por meio de três estados visuais:

| Situação | Estado visual |
|---|---|
| Não existe registro em `socios` | `nao_socio` |
| `status_socio = active` | `socio_ativo` |
| `pending_validation`, `inactive`, `blocked` ou `cancelled` | `socio_inativo` |

`app_new`, `legacy_import` e `manual_admin` são valores internos de `tipo_origem`. Eles explicam como o vínculo surgiu e não devem ser usados como rótulo visual principal.

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

## Planos e fidelidade

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


