# ERD inicial — Domínio de Sócios

Este documento apresenta uma primeira proposta de relacionamento entre entidades.

O objetivo é validar o desenho antes de criar migrations.

---

## Diagrama ERD proposto

```mermaid
erDiagram
    usuarios ||--o| socios : "pode possuir"
    usuarios ||--o{ metodos_pagamento : "cadastra"
    usuarios ||--o{ auditoria_socio : "executa"

    socios ||--o{ assinaturas : "possui"
    socios ||--o{ cobrancas : "recebe"
    socios ||--o{ fidelidade_movimentos : "gera"
    socios ||--o{ beneficios_socio : "possui"
    socios ||--o{ carteirinhas : "emite"
    socios ||--o{ auditoria_socio : "registra"

    planos_associacao ||--o{ assinaturas : "define"

    assinaturas ||--o{ cobrancas : "gera"

    cobrancas ||--o{ fidelidade_movimentos : "pode contar"

    beneficios ||--o{ beneficios_socio : "libera"

    usuarios {
        int id_usuario PK
        string nome
        string email
        string senha
        string status
        timestamp created_at
        timestamp updated_at
    }

    socios {
        int id_socio PK
        int id_usuario FK
        string numero_socio
        string status_socio
        string tipo_origem
        text observacao
        timestamp data_solicitacao
        timestamp data_ativacao
        timestamp data_inativacao
        int validado_por FK
        timestamp created_at
        timestamp updated_at
    }

    planos_associacao {
        int id_plano PK
        string nome
        text descricao
        decimal valor_mensal
        string moeda
        boolean ativo
        timestamp created_at
        timestamp updated_at
    }

    assinaturas {
        int id_assinatura PK
        int id_socio FK
        int id_plano FK
        string status_assinatura
        timestamp data_inicio
        timestamp data_cancelamento
        timestamp proxima_cobranca_em
        string gateway_customer_id
        string gateway_subscription_id
        timestamp created_at
        timestamp updated_at
    }

    metodos_pagamento {
        int id_metodo_pagamento PK
        int id_usuario FK
        string gateway_payment_method_id
        string brand
        string last4
        string expiration_month
        string expiration_year
        boolean is_default
        string status
        timestamp created_at
        timestamp updated_at
    }

    cobrancas {
        int id_cobranca PK
        int id_socio FK
        int id_assinatura FK
        string competencia
        decimal valor
        string moeda
        string status_cobranca
        timestamp scheduled_at
        timestamp due_at
        timestamp paid_at
        timestamp failed_at
        string gateway_invoice_id
        string gateway_payment_id
        timestamp created_at
        timestamp updated_at
    }

    fidelidade_movimentos {
        int id_movimento PK
        int id_socio FK
        int id_cobranca FK
        string tipo_movimento
        int quantidade
        string competencia
        text observacao
        timestamp created_at
    }

    beneficios {
        int id_beneficio PK
        string nome
        text descricao
        string tipo_beneficio
        int requer_mensalidades
        boolean ativo
        timestamp created_at
        timestamp updated_at
    }

    beneficios_socio {
        int id_beneficio_socio PK
        int id_socio FK
        int id_beneficio FK
        string status_beneficio
        timestamp disponivel_em
        timestamp resgatado_em
        timestamp expira_em
        timestamp created_at
        timestamp updated_at
    }

    carteirinhas {
        int id_carteirinha PK
        int id_socio FK
        string codigo_carteirinha
        string status_carteirinha
        timestamp emitida_em
        timestamp valida_ate
        timestamp revogada_em
        string qr_token_hash
        timestamp created_at
        timestamp updated_at
    }

    auditoria_socio {
        int id_auditoria PK
        int id_socio FK
        string acao
        json valor_anterior
        json valor_novo
        int executado_por FK
        string origem
        timestamp created_at
    }
```

---

## Leitura do modelo

### Usuário x Sócio

`usuarios` representa a conta do app.

`socios` representa o vínculo associativo.

Relacionamento sugerido:

```txt
usuarios 1 → 0..1 socios
```

Na primeira versão, é recomendável permitir apenas um sócio ativo/vigente por usuário.

---

## Associação

`socios` concentra o status associativo.

Estados sugeridos:

```txt
pending_validation
active
inactive
blocked
cancelled
```

A associação pode vir de:

```txt
app_new
legacy_import
manual_admin
```

---

## Pagamentos

A assinatura recorrente é separada das cobranças.

```txt
socios → assinaturas → cobrancas
```

Isso permite:

- sócio sem recorrência ativa;
- sócio legado ativo sem gateway inicialmente;
- várias cobranças por assinatura;
- cobranças futuras, pendentes, pagas e falhas.

---

## Métodos de pagamento

`metodos_pagamento` pertence ao usuário, não diretamente ao sócio.

Motivo: método de pagamento é dado de conta/gateway. Caso no futuro exista outra relação financeira, o método pode continuar associado ao usuário.

Nenhum dado sensível deve ser salvo diretamente.

Permitido:

```txt
brand
last4
expiration_month
expiration_year
gateway_payment_method_id
```

Não permitido:

```txt
número completo do cartão
CVV
senha
payload sensível do gateway sem necessidade
```

---

## Fidelidade

`fidelidade_movimentos` é uma ledger/tabela de movimentos.

Isso é melhor do que manter apenas um contador no sócio, porque permite auditoria:

- pagamento contado;
- estorno;
- ajuste manual;
- resgate de benefício.

O progresso pode ser calculado por soma dos movimentos válidos.

---

## Benefícios

`beneficios` é catálogo.

`beneficios_socio` é instância do benefício liberado para um sócio.

Isso permite saber:

- quando liberou;
- se foi resgatado;
- se expirou;
- se foi cancelado.

---

## Carteirinha

`carteirinhas` depende de `socios`.

Regra sugerida:

```txt
Somente sócio active pode ter carteirinha active.
```

A carteirinha pode ser revogada sem apagar histórico.

---

## Auditoria

`auditoria_socio` registra mudanças relevantes.

Exemplos:

```txt
member_created
member_validated
member_activated
member_inactivated
member_cancelled
card_issued
card_revoked
manual_loyalty_adjustment
```

Este ponto será importante quando houver backoffice.

---

## Questões para validação antes das migrations

1. `usuarios 1 → 0..1 socios` é suficiente ou devemos permitir múltiplos vínculos históricos?
2. `numero_socio` será único e obrigatório apenas após ativação?
3. Carteirinha pode ter múltiplas emissões históricas por sócio?
4. A assinatura pertence sempre ao sócio ou pode pertencer ao usuário?
5. Benefícios resgatados devem permanecer para histórico mesmo após cancelamento do sócio?
6. Fidelidade deve ser calculada por ledger ou materializada também no sócio para performance?
7. A base legada terá número de sócio próprio que precisa ser preservado?
