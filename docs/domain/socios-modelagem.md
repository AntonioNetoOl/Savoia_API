# Modelagem do domínio de Sócios — APP Savóia

## 1. Objetivo

Este documento define a primeira proposta de modelagem do domínio de Sócios do APP Savóia.

A intenção é separar corretamente:

- conta de usuário;
- vínculo associativo como sócio;
- validação pela Savóia/sede/backoffice;
- pagamentos e recorrência;
- fidelidade;
- benefícios;
- futura carteirinha digital.

A modelagem aqui ainda é proposta. Antes de criar migrations, este documento deve ser revisado e validado.

---

## 2. Princípio central

Usuário e Sócio não são a mesma coisa.

Um **usuário** é uma pessoa com login no app.

Um **sócio** é um vínculo associativo validado pela Savóia.

Portanto, a tabela `usuarios` deve continuar representando autenticação e dados básicos de conta. A regra de associação deve ficar em tabelas próprias.

---

## 3. Estados de sócio

### Estados usados no app

```txt
nao_socio
socio_inativo
socio_ativo
```

### Estados sugeridos no banco

```txt
not_member
pending_validation
active
inactive
blocked
cancelled
```

### Mapeamento inicial

| Banco | App | Descrição |
|---|---|---|
| `not_member` | `nao_socio` | Usuário sem associação vinculada |
| `pending_validation` | `socio_inativo` | Usuário solicitou associação ou vínculo legado, aguardando validação |
| `inactive` | `socio_inativo` | Sócio existe, mas não está ativo/adimplente |
| `blocked` | `socio_inativo` | Sócio bloqueado administrativamente |
| `cancelled` | `socio_inativo` | Associação cancelada |
| `active` | `socio_ativo` | Sócio validado e ativo |

---

## 4. Entidades propostas

### 4.1 `usuarios`

Tabela existente. Deve continuar sendo a origem da conta do app.

Responsabilidades:

- login;
- nome;
- e-mail;
- senha/hash;
- recuperação de senha;
- status básico de conta.

Não deve concentrar regras completas de sócio.

Campos relevantes esperados:

```txt
id_usuario
nome
email
senha
status
created_at
updated_at
```

---

### 4.2 `socios`

Representa o vínculo associativo do usuário com a Savóia.

Campos sugeridos:

```txt
id_socio
id_usuario
numero_socio
status_socio
tipo_origem
observacao
data_solicitacao
data_ativacao
data_inativacao
validado_por
created_at
updated_at
```

#### `status_socio`

Valores sugeridos:

```txt
pending_validation
active
inactive
blocked
cancelled
```

#### `tipo_origem`

Valores sugeridos:

```txt
app_new
legacy_import
manual_admin
```

Uso:

- `app_new`: usuário pediu associação pelo app;
- `legacy_import`: usuário já era sócio antes do app;
- `manual_admin`: associação criada diretamente pela sede/backoffice.

---

### 4.3 `planos_associacao`

Representa planos possíveis de associação/mensalidade.

Campos sugeridos:

```txt
id_plano
nome
descricao
valor_mensal
moeda
ativo
created_at
updated_at
```

Exemplo:

```txt
Mensalidade Savóia — R$ 35,00
```

---

### 4.4 `assinaturas`

Representa uma assinatura/recorrência de pagamento do sócio.

Campos sugeridos:

```txt
id_assinatura
id_socio
id_plano
status_assinatura
data_inicio
data_cancelamento
proxima_cobranca_em
gateway_customer_id
gateway_subscription_id
created_at
updated_at
```

#### `status_assinatura`

Valores sugeridos:

```txt
pending
active
paused
cancelled
failed
```

Observação: esta tabela não substitui `socios`. Um sócio pode existir sem assinatura ativa, especialmente durante validação ou em cenários de base legada.

---

### 4.5 `metodos_pagamento`

Representa métodos de pagamento tokenizados no gateway.

Nunca armazenar número completo de cartão nem CVV.

Campos sugeridos:

```txt
id_metodo_pagamento
id_usuario
gateway_payment_method_id
brand
last4
expiration_month
expiration_year
is_default
status
created_at
updated_at
```

#### `status`

Valores sugeridos:

```txt
active
expired
removed
invalid
```

---

### 4.6 `cobrancas`

Representa cobranças geradas, incluindo futuras, pendentes, pagas e falhas.

Campos sugeridos:

```txt
id_cobranca
id_socio
id_assinatura
competencia
valor
moeda
status_cobranca
scheduled_at
due_at
paid_at
failed_at
gateway_invoice_id
gateway_payment_id
created_at
updated_at
```

#### `status_cobranca`

Valores sugeridos:

```txt
scheduled
pending
paid
failed
cancelled
refunded
```

Uso:

- `scheduled`: cobrança futura programada pela recorrência;
- `pending`: cobrança aberta/emitida, aguardando confirmação;
- `paid`: pagamento confirmado;
- `failed`: tentativa de cobrança falhou;
- `cancelled`: cobrança cancelada antes de ser paga;
- `refunded`: valor estornado.

---

### 4.7 `fidelidade_movimentos`

Representa o histórico de movimentos que contam ou impactam a fidelidade.

Campos sugeridos:

```txt
id_movimento
id_socio
id_cobranca
tipo_movimento
quantidade
competencia
observacao
created_at
```

#### `tipo_movimento`

Valores sugeridos:

```txt
payment_counted
payment_reversed
manual_adjustment
benefit_redeemed
```

Regra inicial:

- cobrança `paid` válida gera `payment_counted` com quantidade `1`;
- ao completar 12 movimentos válidos, liberar benefício;
- estorno/cancelamento pode gerar reversão.

---

### 4.8 `beneficios`

Catálogo de benefícios disponíveis.

Campos sugeridos:

```txt
id_beneficio
nome
descricao
tipo_beneficio
requer_mensalidades
ativo
created_at
updated_at
```

Exemplo:

```txt
Item grátis na loja
requer_mensalidades = 12
```

---

### 4.9 `beneficios_socio`

Representa benefícios liberados, usados ou expirados para cada sócio.

Campos sugeridos:

```txt
id_beneficio_socio
id_socio
id_beneficio
status_beneficio
disponivel_em
resgatado_em
expira_em
created_at
updated_at
```

#### `status_beneficio`

Valores sugeridos:

```txt
available
redeemed
expired
cancelled
```

---

### 4.10 `carteirinhas`

Representa a carteirinha digital do sócio.

A carteirinha só deve existir para sócio validado/ativo, ou no mínimo só deve ficar ativa quando o sócio estiver ativo.

Campos sugeridos:

```txt
id_carteirinha
id_socio
codigo_carteirinha
status_carteirinha
emitida_em
valida_ate
revogada_em
qr_token_hash
created_at
updated_at
```

#### `status_carteirinha`

Valores sugeridos:

```txt
active
inactive
revoked
expired
```

Observação: o QR Code/token deve ser pensado com cuidado. Não armazenar token sensível em texto puro se ele permitir validação de identidade.

---

### 4.11 `auditoria_socio`

Registra alterações relevantes feitas por backoffice/sede/sistema.

Campos sugeridos:

```txt
id_auditoria
id_socio
acao
valor_anterior
valor_novo
executado_por
origem
created_at
```

Exemplos de ações:

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

---

## 5. Regras de negócio iniciais

### 5.1 Associação

- Um usuário pode existir sem ser sócio.
- Um usuário pode solicitar associação pelo app.
- Um usuário pode ser vinculado a uma associação legada.
- A ativação deve depender de validação pela Savóia/sede/backoffice.
- A tela Sócio deve refletir o estado real da associação.

### 5.2 Pagamentos e recorrência

- A recorrência não deve ser confundida com associação.
- Cobranças futuras devem ser exibidas como `scheduled`.
- Cobranças abertas devem ser `pending`.
- Pagamentos confirmados devem ser `paid`.
- Falhas devem ser `failed`.
- Gateway financeiro será integrado em etapa própria.

### 5.3 Fidelidade

- Apenas mensalidades válidas e pagas contam para fidelidade.
- O marco inicial do benefício é 12 mensalidades válidas.
- Cancelamento, estorno ou ajuste manual precisam ser rastreáveis.

### 5.4 Benefícios

- Benefício deve ser liberado por regra clara.
- Benefício liberado não deve depender apenas da contagem visual no app.
- Toda liberação/resgate deve ser persistida.

### 5.5 Carteirinha

- Carteirinha não deve ser emitida antes da associação validada.
- Carteirinha ativa depende de sócio ativo.
- Se o sócio for bloqueado, cancelado ou expirar, a carteirinha deve refletir isso.

---

## 6. Próximas decisões pendentes

Antes de criar migrations, precisamos decidir:

1. O número de sócio será sequencial interno ou herdado de base legada?
2. Um usuário poderá ter mais de uma associação histórica?
3. Qual será o fluxo exato de validação pela sede?
4. Existe plano único de R$ 35,00 ou haverá múltiplos planos?
5. A recorrência será obrigatória para ser sócio ativo?
6. Sócio legado sem recorrência pode ser ativo?
7. Como tratar inadimplência?
8. A fidelidade conta mensalidades antigas/legadas ou só pagamentos pelo app?
9. Benefício expira?
10. Carteirinha terá validade anual, mensal ou enquanto o sócio estiver ativo?

---

## 7. Ordem recomendada de implementação

1. Validar este documento.
2. Validar fluxos em `socios-fluxos.md`.
3. Validar ERD em `socios-erd.md`.
4. Criar migrations iniciais.
5. Refatorar `GET /api/member/summary` para usar tabelas reais.
6. Refatorar pagamentos/fidelidade para dados persistidos.
7. Só depois iniciar Carteirinha v1.
