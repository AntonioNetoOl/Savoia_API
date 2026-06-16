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
- apoiar o vínculo automático entre usuário do app e sócio legado;
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

- `cpf` deve ser tratado como dado pessoal identificador e de alto impacto operacional.
- O CPF já é obrigatório no cadastro atual do app.
- A aplicação deve evitar expor CPF completo no frontend.
- A decisão inicial aceita CPF normalizado no MVP, com controle de acesso e sem exposição no app.
- A arquitetura alvo deve evoluir para `cpf_hash`, `cpf_encrypted` e `cpf_masked`, conforme documentado em `cpf-seguranca.md`.
- `numero_socio_legado` deve ser preservado para emissão da futura carteirinha.

---

## 3. Associação de usuário com sócio legado

### Decisão

Quando um usuário novo se cadastrar no app, o sistema deverá verificar automaticamente se ele já existe na tabela `socios_legado`.

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

### Vínculo automático

Se o CPF do usuário bater com um CPF em `socios_legado`, o vínculo será automático.

Não haverá etapa manual obrigatória da sede antes de criar o vínculo inicial.

A sede/backoffice entrará depois para atualizar dados operacionais, plano, fidelidade inicial e situação do sócio quando necessário.

### Fluxo esperado

1. Usuário cria conta no app.
2. CPF já é coletado no cadastro obrigatório.
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
7. Sede/backoffice pode atualizar dados necessários, incluindo fidelidade inicial quando aplicável.

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

### Regra de preservação por inadimplência

Se o sócio não pagar, ele possui uma janela de até 30 dias a partir da data original de vencimento para regularizar sem perder a fidelidade acumulada.

Se pagar antes de completar 30 dias de atraso, a fidelidade permanece e o sócio volta ao estado ativo automaticamente.

Se passar de 30 dias sem regularização, a fidelidade zera.

### Implicação técnica

A tabela de fidelidade deve suportar ajustes e reversões auditáveis.

Tipos de movimento necessários:

```txt
payment_counted
payment_reversed
manual_adjustment
legacy_adjustment
benefit_redeemed
loyalty_reset
```

O tipo `legacy_adjustment` representa ajuste realizado pela sede/backoffice para sócios vindos do legado.

O tipo `loyalty_reset` representa zeragem por ultrapassar 30 dias de atraso.

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

Pagamento mensal vence no dia definido da cobrança, por exemplo dia 12.

Se o usuário não pagar, haverá tolerância de 1 semana.

Após essa tolerância, o sócio muda para `inactive` e passa a aparecer no app como `socio_inativo`.

A carteirinha continua existindo, mas reflete status inativo.

Benefícios de sócio ativo ficam indisponíveis enquanto o status estiver inativo.

### Janela de fidelidade

A fidelidade permanece armazenada por até 30 dias a partir da data original de vencimento.

Se o pagamento for regularizado antes de completar 30 dias de atraso:

```txt
pagamento confirmado
→ reativação automática
→ status_socio = active
→ fidelidade preservada
```

Se passar de 30 dias sem regularização:

```txt
atraso > 30 dias
→ fidelidade zera
→ status_socio permanece inactive
```

### Implicação técnica

Fluxo inicial:

```txt
vencimento no dia 12
→ não pagou
→ aguarda 7 dias de tolerância
→ após tolerância, socios.status_socio = inactive
→ até 30 dias do vencimento, fidelidade fica preservada
→ pagamento antes de 30 dias reativa automaticamente
→ sem pagamento após 30 dias, gera loyalty_reset
```

Ainda será necessário definir tecnicamente:

```txt
como o job diário verificará atrasos
como a cobrança será atualizada pelo gateway
qual evento dispara o loyalty_reset
```

---

## 9. Reativação

### Decisão

A reativação será automática após pagamento confirmado.

Não haverá necessidade de ação manual da sede para reativar um sócio que regularizou pagamento dentro da regra definida.

### Fluxo esperado

```txt
pagamento confirmado
→ sistema identifica sócio inactive por inadimplência
→ verifica se pagamento ocorreu dentro da janela de 30 dias
→ status_socio = active
→ assinatura/cobrança fica regularizada
→ fidelidade é preservada se ainda estiver dentro da janela
```

---

## 10. Sistema de gerenciamento

### Decisão atual

Alterações manuais de fidelidade, notificações para sede, auditorias administrativas e regras operacionais de backoffice serão modeladas posteriormente.

O foco inicial permanece no app e na estrutura mínima necessária para suportar o domínio de sócios.

### Implicação técnica

Mesmo que o gerenciamento seja futuro, as tabelas devem nascer preparadas para auditoria e ajustes posteriores.

Por isso, permanecem previstas:

```txt
fidelidade_movimentos
auditoria_socio
```

---

## 11. Planilha legada

### Decisão atual

O layout real da planilha ainda não foi recebido.

O responsável pela base foi acionado e o envio está pendente.

A expectativa é que a planilha contenha dados semelhantes aos já coletados no cadastro do app.

### Implicação técnica

A modelagem deve continuar flexível até o recebimento da planilha.

Campos mínimos esperados:

```txt
numero_socio_legado
nome
cpf
email
telefone
```

Após receber a planilha, será necessário revisar:

```txt
nomes das colunas
tipos de dados
campos obrigatórios
qualidade dos CPFs
duplicidades
status atual do sócio no legado
```

---

## 12. Decisões consolidadas

| Tema | Decisão |
|---|---|
| Número de sócio | Herdado da planilha/base legada inicialmente |
| Tabela de legado | Criar `socios_legado` ou nome equivalente |
| CPF no cadastro | CPF já é obrigatório no cadastro do app |
| Armazenamento de CPF | MVP aceita CPF normalizado com controle; alvo é hash/encrypted/masked |
| Conciliação | Principalmente por CPF |
| Vínculo com legado | Automático quando CPF bater |
| Aprovação prévia da sede | Não é necessária para criar vínculo inicial com legado |
| Vínculo por usuário | Um usuário possui no máximo um registro principal em `socios` |
| Sócio legado | Entra como inativo até validação/atualização pela sede |
| Mudança de plano | Atualiza o mesmo sócio/assinatura, não cria novo sócio |
| Interrupção de pagamento | Mesmo sócio muda para inativo |
| Tolerância de atraso | 1 semana após vencimento |
| Inativação | Após tolerância sem pagamento |
| Reativação | Automática após pagamento confirmado |
| Fidelidade | Conta pagamentos pelo app; legado pode receber ajuste manual pela sede |
| Preservação da fidelidade | Preserva até 30 dias após vencimento original |
| Zeragem da fidelidade | Após mais de 30 dias de atraso |
| Carteirinha | Reflete ativo/inativo; não desaparece automaticamente |
| Inadimplência | Torna sócio inativo e restringe benefícios de ativo |
| Sistema de gerenciamento | Será modelado depois, conforme necessidades do app |
| Layout da planilha | Pendente; esperado como similar ao cadastro atual |

---

## 13. Próximos pontos a decidir

1. Qual será o layout/estrutura real da planilha legada?
2. Reativação após 30 dias exigirá pagar apenas mensalidade atual, débitos antigos ou nova adesão?
3. O vínculo automático por CPF terá alguma rotina de auditoria/notificação para a sede quando o gerenciamento existir?
4. Qual será a estrutura mínima da primeira migration: somente tabelas de sócios/legado ou também cobranças/fidelidade?
