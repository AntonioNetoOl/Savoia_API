# Decisões de negócio — Domínio de Sócios

Este documento registra decisões confirmadas para orientar a modelagem definitiva do banco de dados de sócios.

---

## 1. Número de sócio

### Decisão

O número de sócio será inicialmente **herdado da base legada**.

A Savóia já possui uma planilha de sócios. Essa planilha será usada para popular uma tabela específica de legado, inicialmente proposta como:

```txt
socios_legado
```

A tabela de legado servirá como base de conciliação para identificar se um novo usuário do app já era sócio antes do aplicativo.

---

## 2. Tabela de sócios legados

### Objetivo

Armazenar a base importada da planilha atual de sócios.

### Responsabilidades

- preservar o número atual de sócio;
- armazenar dados de identificação vindos da planilha;
- permitir busca por dados únicos, principalmente CPF;
- apoiar o vínculo automático ou semi-automático entre usuário do app e sócio legado;
- manter rastreabilidade da origem dos dados.

### Campos iniciais sugeridos

```txt
id_socio_legado
numero_socio_legado
nome
cpf
email
telefone
status_legado
origem_importacao
linha_origem
importado_em
vinculado_em
id_usuario_vinculado
created_at
updated_at
```

### Observações

- `cpf` deve ser tratado como dado sensível.
- A aplicação deve evitar expor CPF completo no frontend.
- Recomenda-se armazenar CPF normalizado, e futuramente avaliar criptografia/hash dependendo da estratégia de segurança.
- `numero_socio_legado` deve ser preservado para emissão da futura carteirinha.

---

## 3. Associação de usuário com sócio legado

### Decisão

Quando um usuário novo se cadastrar no app, o sistema deverá verificar se ele já existe na tabela `socios_legado`.

A verificação inicial será por dados únicos, com prioridade para:

```txt
cpf
```

Outros campos podem apoiar conciliação, mas não devem substituir CPF como identificador principal sem validação:

```txt
email
telefone
nome
```

### Fluxo esperado

1. Usuário cria conta no app.
2. Usuário informa CPF em etapa futura do cadastro/perfil.
3. Backend normaliza o CPF.
4. Sistema busca CPF em `socios_legado`.
5. Se encontrar, cria ou atualiza registro em `socios` com:

```txt
tipo_origem = legacy_import
status_socio = inactive
numero_socio = socios_legado.numero_socio_legado
id_socio_legado = socios_legado.id_socio_legado
```

6. App exibe o usuário como `socio_inativo`.
7. Sede/backoffice valida e atualiza dados necessários, incluindo fidelidade inicial quando aplicável.

---

## 4. Múltiplas associações por usuário

### Decisão

Um usuário **não deve ter mais de uma associação histórica ativa/registrada como vínculo principal**.

A regra inicial será:

```txt
usuarios 1 → 0..1 socios
```

Se o usuário já for sócio no legado, ele entra como sócio legado vinculado.

Se estiver pagando e parar, o mesmo registro de sócio muda para `inactive`.

Se mudar de plano, o mesmo sócio muda de plano/assinatura; não se cria outro sócio.

### Implicação técnica

A tabela `socios` deve ter restrição de unicidade para `id_usuario`, pelo menos enquanto esta regra permanecer válida.

---

## 5. Sócio legado sem recorrência

### Esclarecimento

A pergunta “sócio legado pode ser ativo sem recorrência?” significa:

> Um sócio importado da planilha antiga poderia aparecer como `socio_ativo` mesmo sem ter pagamento recorrente cadastrado no app?

### Decisão pendente/recomendada

Pelo fluxo definido, o sócio legado entra inicialmente como:

```txt
status_socio = inactive
```

Depois a sede/backoffice deverá validar e atualizar a situação.

A recorrência pelo app não deve ser usada como única fonte de verdade para dizer se alguém é sócio ou não. Porém, na regra operacional futura, poderemos decidir se a ativação exige recorrência ativa.

Neste momento, a decisão confirmada é:

```txt
Sócio legado entra como inativo até validação/atualização pela sede.
```

---

## 6. Fidelidade

### Decisão

A fidelidade contará **somente pagamentos feitos pelo app**.

Para sócios legados, a sede/backoffice poderá atualizar manualmente o número de mensalidades pagas ou saldo inicial de fidelidade através de um sistema de gerenciamento paralelo ao app, que será desenvolvido depois.

### Implicação técnica

A tabela de fidelidade deve suportar ajustes manuais auditáveis.

Tipos de movimento necessários:

```txt
payment_counted
payment_reversed
manual_adjustment
legacy_adjustment
benefit_redeemed
```

O tipo `legacy_adjustment` representa ajuste realizado pela sede/backoffice para sócios vindos do legado.

---

## 7. Carteirinha

### Decisão

A carteirinha depende do status do sócio, mas não deixa de existir quando o sócio fica inativo.

Se o sócio estiver ativo, a carteirinha deve indicar sócio ativo.

Se o sócio estiver inativo, a carteirinha deve indicar sócio inativo.

A carteirinha de sócio inativo impede acesso a benefícios exclusivos de sócio ativo.

### Implicação técnica

A carteirinha não deve ser simplesmente apagada ou bloqueada imediatamente quando houver inadimplência.

Ela deve refletir o estado atual:

```txt
socio_ativo   → carteirinha exibe ativo
socio_inativo → carteirinha exibe inativo
```

---

## 8. Inadimplência

### Decisão

Inadimplência não bloqueia a carteirinha imediatamente no sentido de remover a carteirinha.

O usuário passa a ser `socio_inativo`.

Esse estado será refletido na carteirinha e usado para impedir benefícios de sócio ativo.

### Implicação técnica

Fluxo inicial:

```txt
pagamento falhou / recorrência interrompida
→ sócio muda para inactive conforme regra de negócio
→ carteirinha continua existindo, mas exibe status inativo
→ benefícios de sócio ativo ficam indisponíveis
```

Ainda será necessário definir a regra de tolerância antes de mudar para inativo:

```txt
quantos dias de atraso?
quantas tentativas de cobrança?
quem pode reativar?
```

---

## 9. Decisões consolidadas

| Tema | Decisão |
|---|---|
| Número de sócio | Herdado da planilha/base legada inicialmente |
| Tabela de legado | Criar `socios_legado` ou nome equivalente |
| Conciliação | Principalmente por CPF |
| Vínculo por usuário | Um usuário possui no máximo um registro principal em `socios` |
| Sócio legado | Entra como inativo até validação/atualização pela sede |
| Mudança de plano | Atualiza o mesmo sócio/assinatura, não cria novo sócio |
| Interrupção de pagamento | Mesmo sócio muda para inativo |
| Fidelidade | Conta pagamentos pelo app; legado pode receber ajuste manual pela sede |
| Carteirinha | Reflete ativo/inativo; não desaparece automaticamente |
| Inadimplência | Torna sócio inativo e restringe benefícios de ativo |

---

## 10. Próximos pontos a decidir

1. O CPF será obrigatório no cadastro inicial ou apenas na etapa de associação/perfil?
2. Qual formato de armazenamento seguro de CPF será adotado?
3. Qual será o layout/estrutura da planilha legada?
4. Haverá tela de revisão de possíveis matches antes de vincular automaticamente?
5. Quem poderá alterar mensalidades de fidelidade no sistema de gerenciamento?
6. Qual regra define quando inadimplência muda o sócio para inativo?
7. Reativação será automática após pagamento ou manual pela sede?
