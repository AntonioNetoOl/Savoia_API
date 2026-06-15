# ERD inicial — Domínio de Sócios

Este documento apresenta a proposta inicial de relacionamento entre entidades do domínio de sócios.

O objetivo é validar o desenho antes de criar migrations.

---

## Diagrama ERD proposto

```mermaid
erDiagram
    usuarios ||--o| socios : "possui no maximo um"
    usuarios ||--o{ metodos_pagamento : "cadastra"
    usuarios ||--o{ auditoria_socio : "executa"
    usuarios ||--o| socios_legado : "pode vincular"

    socios_legado ||--o| socios : "origina vinculo"

    socios ||--o{ assinaturas : "possui"
    socios ||--o{ cobrancas : "recebe"
    socios ||--o{ fidelidade_movimentos : "gera"
    socios ||--o{ beneficios_socio : "possui"
    socios ||--o{ carteirinhas : "exibe"
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

    socios_legado {
        int id_socio_legado PK
        string numero_socio_legado
        string nome
        string cpf
        string email
        string telefone
        string status_legado
        string origem_importacao
        int linha_origem
        timestamp importado_em
        timestamp vinculado_em
        int id_usuario_vinculado FK
        timestamp created_at
        timestamp updated_at
    }

    socios {
        int id_socio PK
        int id_usuario FK
        int id_socio_legado FK
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

Relacionamento confirmado para a primeira versão:

```txt
usuarios 1 → 0..1 socios
```

Um usuário não deve possuir múltiplos vínculos principais de sócio. Se o sócio muda de plano, interrompe pagamento ou é reativado, o mesmo registro de `socios` deve ser atualizado.

---

## Sócios legados

`socios_legado` representa a planilha/base atual de sócios da Savóia.

Essa tabela deve preservar:

- número de sócio legado;
- CPF ou dado único usado para conciliação;
- dados auxiliares da planilha;
- vínculo futuro com usuário do app.

Fluxo esperado:

```txt
usuário informa CPF
→ sistema busca em socios_legado
→ se encontrar, cria socios com tipo_origem = legacy_import
→ numero_socio recebe numero_socio_legado
→ status_socio inicia como inactive
→ sede/backoffice valida e ajusta fidelidade quando necessário
```

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

Para legado, a regra inicial é:

```txt
tipo_origem = legacy_import
status_socio = inactive
```

---

## Pagamentos

A assinatura recorrente é separada das cobranças.

```txt
socios → assinaturas → cobrancas
```

Isso permite:

- sócio inativo sem apagar histórico;
- mudança de plano sem criar novo sócio;
- várias cobranças por assinatura;
- cobranças futuras, pendentes, pagas e falhas.

---

## Métodos de pagamento

`metodos_pagamento` pertence ao usuário, não diretamente ao sócio.

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

A fidelidade contará pagamentos pelo app.

Para sócio legado, a sede/backoffice poderá criar ajuste manual auditável.

Tipos importantes:

```txt
payment_counted
payment_reversed
manual_adjustment
legacy_adjustment
benefit_redeemed
```

---

## Benefícios

`beneficios` é catálogo.

`beneficios_socio` é instância do benefício liberado para um sócio.

Benefícios de sócio ativo devem depender do status atual do sócio.

---

## Carteirinha

`carteirinhas` depende de `socios`.

Regra atualizada:

```txt
A carteirinha existe para refletir o status atual do sócio.
```

Se o sócio estiver ativo, a carteirinha mostra ativo.

Se o sócio estiver inativo, a carteirinha mostra inativo.

A carteirinha de sócio inativo não deve permitir benefícios exclusivos de sócio ativo.

---

## Auditoria

`auditoria_socio` registra mudanças relevantes.

Exemplos:

```txt
member_created
legacy_member_linked
member_validated
member_activated
member_inactivated
member_cancelled
card_issued
card_status_changed
manual_loyalty_adjustment
legacy_loyalty_adjustment
```

Este ponto será importante quando houver backoffice.

---

## Questões para validação antes das migrations

1. CPF será obrigatório no cadastro inicial ou somente na etapa de associação/perfil?
2. Como será armazenado CPF com segurança?
3. Qual será o formato exato da planilha legada?
4. O vínculo com legado será automático quando CPF bater ou exigirá revisão da sede?
5. Qual regra de atraso muda sócio para inativo?
6. Reativação por pagamento será automática ou manual?
7. Carteirinha terá código próprio além do número de sócio?
