# DER — Domínio de Sócios

Este documento apresenta o **Diagrama de Entidade e Relacionamento (DER)** do domínio de sócios do APP Savóia.

O objetivo é facilitar manutenção, onboarding e evolução futura do backend, mantendo uma visão única dos relacionamentos entre cadastro, associação, planos, pagamentos, fidelidade e brindes.

> Fonte de verdade: este DER foi montado a partir das migrations versionadas do projeto. Em caso de divergência, a estrutura efetivamente criada pelas migrations prevalece.

## Escopo

O diagrama cobre as tabelas relacionadas ao domínio de sócios atualmente existentes:

- `usuarios`;
- `socios_legado`;
- `planos_associacao`;
- `socios`;
- `auditoria_socio`;
- `metodos_pagamento`;
- `assinaturas`;
- `cobrancas`;
- `fidelidade_movimentos`;
- `brindes_fidelidade_socio`.

A tabela `usuarios` já existia antes das migrations do domínio de sócios. Por isso, o diagrama mostra apenas os campos de `usuarios` relevantes para os relacionamentos deste domínio, e não pretende documentar a tabela inteira.

## DER visual

```mermaid
erDiagram
    USUARIOS {
        int id_usuario PK
        varchar nome
        varchar email
        varchar cpf
        varchar status
    }

    SOCIOS_LEGADO {
        bigint id_socio_legado PK
        varchar numero_socio_legado UK
        varchar cpf_normalizado UK
        varchar cpf_hash UK
        int id_usuario_vinculado FK
        varchar status_legado
        timestamptz vinculado_em
    }

    PLANOS_ASSOCIACAO {
        bigint id_plano PK
        varchar codigo_plano UK
        varchar nome UK
        numeric valor_mensal
        char moeda
        numeric percentual_desconto_loja
        int mensalidades_para_brinde
        text descricao_brinde
        boolean ativo
    }

    SOCIOS {
        bigint id_socio PK
        int id_usuario FK,UK
        bigint id_socio_legado FK,UK
        bigint id_plano_atual FK
        varchar numero_socio UK
        varchar status_socio
        varchar tipo_origem
        timestamptz data_solicitacao
        timestamptz data_ativacao
        timestamptz data_inativacao
        timestamptz inativo_desde
        timestamptz fidelidade_preservada_ate
        int validado_por FK
    }

    AUDITORIA_SOCIO {
        bigint id_auditoria PK
        bigint id_socio FK
        varchar acao
        jsonb valor_anterior
        jsonb valor_novo
        int executado_por FK
        varchar origem
        inet ip
        text user_agent
        timestamptz created_at
    }

    METODOS_PAGAMENTO {
        bigint id_metodo_pagamento PK
        int id_usuario FK
        varchar gateway_payment_method_id UK
        varchar brand
        char last4
        boolean is_default
        varchar status
    }

    ASSINATURAS {
        bigint id_assinatura PK
        bigint id_socio FK
        bigint id_plano FK
        bigint id_metodo_pagamento FK
        varchar status_assinatura
        timestamptz data_inicio
        date proxima_cobranca_em
        varchar gateway_customer_id
        varchar gateway_subscription_id UK
    }

    COBRANCAS {
        bigint id_cobranca PK
        bigint id_socio FK
        bigint id_assinatura FK
        date competencia
        numeric valor
        char moeda
        varchar status_cobranca
        date due_at
        date tolerance_until
        date loyalty_preserved_until
        timestamptz paid_at
        varchar gateway_invoice_id UK
        varchar gateway_payment_id UK
        varchar origem
    }

    FIDELIDADE_MOVIMENTOS {
        bigint id_movimento PK
        bigint id_socio FK
        bigint id_cobranca FK
        varchar tipo_movimento
        int quantidade
        date competencia
        text observacao
        timestamptz created_at
    }

    BRINDES_FIDELIDADE_SOCIO {
        bigint id_brinde_socio PK
        bigint id_socio FK
        bigint id_plano FK
        date ciclo_inicio_em
        date ciclo_fim_em
        int mensalidades_exigidas
        text descricao_brinde
        varchar status_brinde
        timestamptz disponivel_em
        timestamptz resgatado_em
        timestamptz expira_em
    }

    USUARIOS ||--o| SOCIOS : "possui"
    USUARIOS o|--o{ SOCIOS_LEGADO : "vinculo legado"
    USUARIOS o|--o{ SOCIOS : "valida"
    USUARIOS ||--o{ METODOS_PAGAMENTO : "cadastra"
    USUARIOS o|--o{ AUDITORIA_SOCIO : "executa"

    SOCIOS_LEGADO o|--o| SOCIOS : "origina"
    PLANOS_ASSOCIACAO o|--o{ SOCIOS : "plano atual"

    SOCIOS o|--o{ AUDITORIA_SOCIO : "possui historico"
    SOCIOS ||--o{ ASSINATURAS : "possui"
    SOCIOS ||--o{ COBRANCAS : "recebe"
    SOCIOS ||--o{ FIDELIDADE_MOVIMENTOS : "acumula"
    SOCIOS ||--o{ BRINDES_FIDELIDADE_SOCIO : "recebe"

    PLANOS_ASSOCIACAO ||--o{ ASSINATURAS : "contratado em"
    PLANOS_ASSOCIACAO o|--o{ BRINDES_FIDELIDADE_SOCIO : "define brinde"

    METODOS_PAGAMENTO o|--o{ ASSINATURAS : "utilizado por"
    ASSINATURAS o|--o{ COBRANCAS : "gera"
    COBRANCAS o|--o{ FIDELIDADE_MOVIMENTOS : "origina"
```

## Leitura rápida do modelo

### `usuarios`

Representa a **conta de acesso ao app**.

Usuário e sócio são conceitos diferentes:

```text
usuario = conta/login
socio   = vinculo associativo com a Savoia
```

Um usuário pode existir sem possuir registro em `socios`.

### `socios`

É a entidade central do vínculo associativo.

Ela relaciona:

- o usuário autenticável (`id_usuario`);
- um registro legado opcional (`id_socio_legado`);
- o plano atual opcional (`id_plano_atual`);
- número e status do sócio;
- datas de solicitação, ativação e inativação;
- origem do vínculo;
- janela de preservação de fidelidade.

A unicidade de `socios.id_usuario` garante fisicamente a regra:

```text
um usuario pode ter no maximo um registro em socios
```

Estados atualmente aceitos em `status_socio`:

```text
pending_validation
active
inactive
blocked
cancelled
```

Esses são estados internos. A API apresenta `active` como `socio_ativo`; apresenta `pending_validation`, `inactive`, `blocked` e `cancelled` como `socio_inativo`; e usa `nao_socio` quando não existe registro em `socios`.

`tipo_origem`, incluindo `legacy_import`, descreve a origem do vínculo e não é um estado visual.

### `socios_legado`

Armazena a base histórica/importada de sócios antigos.

O vínculo com o usuário é feito principalmente por CPF no fluxo atual. Um registro legado pode posteriormente ser relacionado a um registro real em `socios`.

A coluna `id_socio_legado` em `socios` possui índice único quando preenchida, impedindo que o mesmo registro legado seja usado por dois registros de sócio.

### `planos_associacao`

É o catálogo de planos.

Atualmente concentra dados como:

- código do plano;
- nome;
- valor mensal;
- moeda;
- percentual de desconto nas lojas;
- quantidade de mensalidades para liberar o brinde;
- descrição do brinde;
- status ativo/inativo.

Os planos atuais são `mutley` (R$ 30,00 e 10% de desconto), `dick` (R$ 50,00 e 15%) e `vigarista` (R$ 75,00 e 20%). Todos usam a regra de brinde após 12 mensalidades consecutivas pagas.

As regras completas estão em [Benefícios e brindes de fidelidade](./beneficios-fidelidade.md).

### `auditoria_socio`

É o histórico de mudanças relevantes do vínculo associativo.

Enquanto `socios` representa **como o vínculo está agora**, `auditoria_socio` registra **como ele chegou ao estado atual**.

Exemplos de eventos:

```text
legacy_member_linked
association_requested
regularization_requested
```

A auditoria pode registrar:

- valor anterior;
- valor novo;
- usuário que executou a ação;
- origem (`app`, `sistema`, `backoffice`, `importacao`, `gateway`);
- IP;
- user-agent;
- data/hora.

### `metodos_pagamento`

Representa referências tokenizadas de métodos de pagamento.

Não deve armazenar número completo de cartão nem CVV.

Um usuário pode possuir vários métodos, mas existe índice parcial que permite apenas um método ativo marcado como padrão por usuário.

### `assinaturas`

Representa a **recorrência** de um sócio em um plano.

Uma assinatura aponta para:

- um sócio;
- um plano;
- opcionalmente um método de pagamento.

Existe índice parcial garantindo no máximo uma assinatura corrente por sócio nos estados:

```text
pending
active
paused
failed
```

### `cobrancas`

Representa cada cobrança individual de uma competência.

Exemplo conceitual:

```text
assinatura Mutley
  -> cobranca 09/2026
  -> cobranca 10/2026
  -> cobranca 11/2026
```

Uma cobrança sempre pertence a um sócio e pode estar vinculada a uma assinatura.

Estados aceitos:

```text
scheduled
pending
paid
failed
cancelled
refunded
```

Ela também possui campos preparados para tolerância de inadimplência e preservação de fidelidade.

### `fidelidade_movimentos`

Funciona como um **ledger/extrato de fidelidade**.

Em vez de guardar apenas um contador final, registra os movimentos que compõem o saldo:

```text
+1 payment_counted
-1 payment_reversed
+N manual_adjustment
-N loyalty_reset
```

Um movimento pertence a um sócio e pode apontar para a cobrança que o originou.

### `brindes_fidelidade_socio`

Representa um direito a brinde efetivamente liberado para um sócio.

É separado dos benefícios gerais do plano.

Estados aceitos:

```text
available
redeemed
cancelled
expired
```

O resgate é presencial na sede e sujeito à disponibilidade de estoque.

## Relacionamentos físicos e comportamento de deleção

| Origem | FK | Destino | Cardinalidade física relevante | `ON DELETE` |
|---|---|---|---|---|
| `socios` | `id_usuario` | `usuarios` | usuário 1 -> 0..1 sócio | `CASCADE` |
| `socios` | `id_socio_legado` | `socios_legado` | 0..1 <-> 0..1 por índice único | `SET NULL` |
| `socios` | `id_plano_atual` | `planos_associacao` | plano 1 -> N sócios | `SET NULL` |
| `socios` | `validado_por` | `usuarios` | usuário 1 -> N validações | `SET NULL` |
| `socios_legado` | `id_usuario_vinculado` | `usuarios` | legado 0..1 -> usuário | `SET NULL` |
| `auditoria_socio` | `id_socio` | `socios` | sócio 1 -> N auditorias | `SET NULL` |
| `auditoria_socio` | `executado_por` | `usuarios` | usuário 1 -> N auditorias | `SET NULL` |
| `metodos_pagamento` | `id_usuario` | `usuarios` | usuário 1 -> N métodos | `CASCADE` |
| `assinaturas` | `id_socio` | `socios` | sócio 1 -> N assinaturas históricas | `CASCADE` |
| `assinaturas` | `id_plano` | `planos_associacao` | plano 1 -> N assinaturas | `RESTRICT` |
| `assinaturas` | `id_metodo_pagamento` | `metodos_pagamento` | método 1 -> N assinaturas | `SET NULL` |
| `cobrancas` | `id_socio` | `socios` | sócio 1 -> N cobranças | `CASCADE` |
| `cobrancas` | `id_assinatura` | `assinaturas` | assinatura 1 -> N cobranças | `SET NULL` |
| `fidelidade_movimentos` | `id_socio` | `socios` | sócio 1 -> N movimentos | `CASCADE` |
| `fidelidade_movimentos` | `id_cobranca` | `cobrancas` | cobrança 1 -> N movimentos possíveis | `SET NULL` |
| `brindes_fidelidade_socio` | `id_socio` | `socios` | sócio 1 -> N brindes/ciclos | `CASCADE` |
| `brindes_fidelidade_socio` | `id_plano` | `planos_associacao` | plano 1 -> N brindes | `SET NULL` |

## Restrições importantes de integridade

### Um único sócio por usuário

Garantido por:

```text
ux_socios_id_usuario
```

### Um único uso de registro legado em `socios`

Garantido por:

```text
ux_socios_id_socio_legado
```

quando `id_socio_legado` não é nulo.

### Uma assinatura corrente por sócio

Garantido por:

```text
ux_assinaturas_socio_corrente
```

para assinaturas em `pending`, `active`, `paused` ou `failed`.

### Um método de pagamento padrão ativo por usuário

Garantido por:

```text
ux_metodos_pagamento_default_por_usuario
```

## Pontos de atenção para evoluções futuras

### Vínculo de `socios_legado` com `usuarios`

`id_usuario_vinculado` possui índice de busca, mas **não possui constraint `UNIQUE`** na migration atual.

O fluxo automático atual protege o vínculo em nível de serviço, porém o banco, isoladamente, permite que mais de uma linha de `socios_legado` referencie o mesmo usuário.

Caso a regra definitiva seja 1:1 também nesse vínculo auxiliar, uma migration futura pode reforçar essa restrição no banco.

### Duplicidade de cobrança por competência

A estrutura atual não possui índice único em algo como:

```text
(id_socio, competencia)
```

ou:

```text
(id_assinatura, competencia)
```

Quando a geração automática de cobranças for implementada, a estratégia de idempotência deve ser definida antes de produção e, se adequado, reforçada com constraint/índice no banco.

### Idempotência da fidelidade

`fidelidade_movimentos` é um ledger, mas ainda não possui uma chave única que impeça, por exemplo, contabilizar a mesma cobrança duas vezes em eventos concorrentes.

Antes da integração financeira real, deverá ser definida a chave de idempotência do movimento financeiro/fidelidade.

## O que ainda não faz parte deste DER

Ainda não existem tabelas definitivas para:

- carteirinha digital;
- QR Code;
- estoque real de brindes;
- backoffice/sistema de gerenciamento;
- cupom para loja online.

Essas entidades devem ser incorporadas ao DER somente quando forem efetivamente modeladas e versionadas por migration.

## Fontes no repositório

- [`migrations/202606151_member_core.sql`](../../migrations/202606151_member_core.sql)
- [`migrations/202606162_member_finance_loyalty.sql`](../../migrations/202606162_member_finance_loyalty.sql)
- [`docs/domain/beneficios-fidelidade.md`](./beneficios-fidelidade.md)

## Regra de manutenção deste documento

Sempre que uma migration adicionar, remover ou alterar:

- tabela do domínio de sócios;
- foreign key;
- cardinalidade;
- constraint de unicidade relevante;
- comportamento `ON DELETE`;

este DER deve ser atualizado na mesma PR da mudança de schema.
