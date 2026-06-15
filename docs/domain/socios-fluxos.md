# Fluxos do domínio de Sócios — APP Savóia

Este documento descreve os fluxos principais antes da criação das tabelas e migrations.

---

## 1. Fluxo: usuário novo quer virar sócio

### Objetivo

Permitir que um usuário com conta no app solicite associação.

### Etapas

1. Usuário cria conta no app.
2. Usuário acessa a área Sócio.
3. App exibe estado `nao_socio`.
4. Usuário solicita associação.
5. Sistema cria registro em `socios` com status `pending_validation`.
6. Backoffice/sede analisa a solicitação.
7. Backoffice aprova ou reprova.
8. Se aprovado, status muda para `active`.
9. App passa a exibir `socio_ativo`.

### Estados envolvidos

```txt
nao_socio → socio_inativo → socio_ativo
```

### Pontos de atenção

- A solicitação não deve ativar automaticamente a associação.
- A validação deve ficar registrada em auditoria.
- Pode haver necessidade de documentos ou confirmação manual, ainda pendente de definição.

---

## 2. Fluxo: usuário já era sócio antes do app

### Objetivo

Permitir vínculo de base legada.

### Etapas

1. Usuário cria conta no app.
2. Usuário informa dados para localizar associação antiga.
3. Sistema cria ou associa registro em `socios` com `tipo_origem = legacy_import`.
4. Status inicial fica `pending_validation`.
5. Backoffice/sede valida o vínculo.
6. Se confirmado, status muda para `active`.
7. Número de sócio pode ser preservado da base legada.

### Pontos de atenção

- Evitar duplicidade de sócios.
- Definir chaves de conciliação: CPF, e-mail, nome completo, telefone ou número antigo de sócio.
- A base legada ainda precisa ser compreendida antes de implementação.

---

## 3. Fluxo: validação pela sede/backoffice

### Objetivo

Controlar ativação real de associação.

### Etapas

1. Backoffice lista solicitações pendentes.
2. Backoffice abre detalhe do solicitante.
3. Backoffice valida dados.
4. Backoffice aprova, reprova ou solicita ajuste.
5. Sistema atualiza `socios.status_socio`.
6. Sistema grava evento em `auditoria_socio`.
7. App reflete novo estado no endpoint `GET /api/member/summary`.

### Estados possíveis

```txt
pending_validation → active
pending_validation → inactive
pending_validation → cancelled
active → inactive
active → blocked
active → cancelled
```

### Pontos de atenção

- Quem validou deve ficar registrado.
- Toda alteração relevante precisa de auditoria.
- A primeira versão pode não ter backoffice completo, mas o modelo precisa suportar isso.

---

## 4. Fluxo: sócio ativa recorrência

### Objetivo

Permitir mensalidade recorrente quando houver gateway financeiro.

### Etapas

1. Sócio ativo acessa pagamentos.
2. Sócio cadastra método de pagamento via gateway.
3. Gateway retorna token/id seguro do método.
4. Sistema salva apenas metadados seguros em `metodos_pagamento`.
5. Sistema cria `assinaturas` com status `active`.
6. Sistema agenda próxima cobrança em `cobrancas` com status `scheduled`.
7. App exibe cobrança em Próximos lançamentos.

### Pontos de atenção

- Não armazenar número completo de cartão.
- Não armazenar CVV.
- Gateway deve ser o responsável pela tokenização.
- A recorrência pode existir separada do status da associação.

---

## 5. Fluxo: cobrança mensal é gerada

### Objetivo

Representar lançamentos futuros, cobranças abertas e histórico.

### Etapas

1. Assinatura ativa possui `proxima_cobranca_em`.
2. Sistema cria uma cobrança `scheduled`.
3. Na data programada, gateway tenta cobrar.
4. Cobrança muda para `pending`, `paid` ou `failed`, conforme retorno.
5. App atualiza Histórico e Próximos lançamentos.

### Estados de cobrança

```txt
scheduled → pending → paid
scheduled → pending → failed
scheduled → cancelled
paid → refunded
```

### Pontos de atenção

- `scheduled` não é dívida, é previsão.
- `pending` é cobrança aberta/aguardando confirmação.
- `paid` é pagamento confirmado.
- `failed` pode exigir nova tentativa ou ação do usuário.

---

## 6. Fluxo: pagamento confirmado conta para fidelidade

### Objetivo

Liberar benefício após 12 mensalidades válidas.

### Etapas

1. Cobrança muda para `paid`.
2. Sistema verifica se a cobrança é válida para fidelidade.
3. Sistema cria movimento `payment_counted` em `fidelidade_movimentos`.
4. Sistema recalcula progresso.
5. Ao atingir 12 mensalidades válidas, sistema libera benefício em `beneficios_socio`.
6. App exibe benefício disponível.

### Pontos de atenção

- Pagamento estornado precisa reverter fidelidade.
- Ajustes manuais precisam ficar auditáveis.
- Base legada pode ou não entrar na contagem, decisão pendente.

---

## 7. Fluxo: benefício é liberado

### Objetivo

Criar benefício disponível para o sócio.

### Etapas

1. Sistema identifica regra atingida.
2. Sistema cria `beneficios_socio` com status `available`.
3. App exibe benefício disponível.
4. Sócio resgata benefício.
5. Sistema altera status para `redeemed`.
6. Resgate fica registrado.

### Pontos de atenção

- Definir se benefício expira.
- Definir se benefício é acumulável.
- Definir quem confirma o resgate: app, loja, backoffice ou validação manual.

---

## 8. Fluxo: carteirinha é emitida

### Objetivo

Emitir carteirinha digital apenas para sócio ativo.

### Pré-condições

```txt
socios.status_socio = active
```

### Etapas

1. Sistema identifica sócio ativo.
2. Sistema cria registro em `carteirinhas`.
3. Carteirinha recebe código único.
4. Carteirinha recebe status `active`.
5. App exibe carteirinha.
6. Se o sócio ficar inativo/bloqueado/cancelado, carteirinha é inativada ou revogada.

### Pontos de atenção

- Definir layout e dados visíveis.
- Definir validade.
- Definir QR Code/token.
- Definir como validar carteirinha em eventos/sede/loja.

---

## 9. Fluxo: sócio fica inadimplente/inativo

### Objetivo

Definir impacto de falhas de pagamento e status associativo.

### Etapas possíveis

1. Cobrança falha.
2. Sistema registra `failed`.
3. Sistema pode tentar nova cobrança.
4. Após regra definida, assinatura pode ficar `failed` ou `paused`.
5. Sócio pode permanecer ativo por tolerância ou virar `inactive`.
6. Carteirinha e benefícios podem ser limitados conforme regra.

### Decisões pendentes

- Quantos dias de tolerância?
- Quantas tentativas de cobrança?
- Inadimplência suspende carteirinha imediatamente?
- Benefícios disponíveis são preservados ou bloqueados?

---

## 10. Fluxo: cancelamento

### Objetivo

Permitir cancelamento controlado de associação/recorrência.

### Etapas

1. Sócio solicita cancelamento ou backoffice inicia cancelamento.
2. Sistema cancela assinatura, se existir.
3. Sistema altera status do sócio, conforme regra.
4. Carteirinha é inativada/revogada.
5. Benefícios podem expirar/cancelar, conforme regra.
6. Evento é registrado em auditoria.

### Pontos de atenção

- Cancelamento da recorrência não necessariamente significa cancelamento imediato da associação.
- É preciso definir política de vigência até o fim do ciclo pago.

---

## 11. Fluxos que ainda precisam de definição do negócio

1. Solicitação de associação exige aprovação sempre?
2. Usuário legado pode ser ativado automaticamente se a base for confiável?
3. Quais dados serão usados para validar sócio legado?
4. O número de sócio será gerado ou herdado?
5. Quais regras de inadimplência afetam carteirinha?
6. Carteirinha tem validade fixa?
7. Benefício de fidelidade pode acumular?
8. A fidelidade considera histórico antes do app?
9. Haverá múltiplos planos de associação?
10. Associação pode estar ativa sem recorrência?
