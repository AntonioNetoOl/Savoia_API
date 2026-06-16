# Benefícios e brindes de fidelidade — APP Savóia

Este documento registra a regra correta de benefícios e brindes para evitar ambiguidade na modelagem de banco.

---

## 1. Conceitos

No contexto da associação Savóia, existem dois conceitos diferentes:

```txt
benefícios gerais
brinde de fidelidade
```

Eles não devem ser tratados como a mesma coisa no banco.

---

## 2. Benefícios gerais do sócio em dia

Todo sócio em dia tem acesso a benefícios gerais, conforme disponibilidade e regra operacional.

Exemplos informados:

```txt
- desconto em ingresso no Allianz, quando disponível
- desconto em caravanas
- desconto em eventos da torcida
- desconto nas lojas da torcida conforme plano
```

Esses benefícios dependem principalmente de:

```txt
status_socio = active
plano atual do sócio
regras comerciais vigentes
```

Para o MVP, eles podem ser exibidos no app como informação institucional, sem exigir uma tabela individual de resgate por usuário.

---

## 3. Planos informados

### Plano Mutley

```txt
valor_mensal = 30.00
percentual_desconto_loja = 10
brinde após 12 mensalidades pagas = 1 Boné ou Pescador ou Touca
```

### Plano Dick

```txt
valor_mensal = 50.00
percentual_desconto_loja = 15
brinde após 12 mensalidades pagas = 1 Camiseta ou Regata ou Bermuda
```

### Plano Vigarista

```txt
valor_mensal = 75.00
percentual_desconto_loja = 20
brinde após 12 mensalidades pagas = 1 Agasalho ou Calça
```

---

## 4. Brinde de fidelidade

O brinde de fidelidade é liberado após:

```txt
12 mensalidades consecutivas pagas, sem interrupções
```

A regra correta é:

```txt
pagou 12 mensalidades consecutivas
→ brinde fica disponível para retirada
→ retirada deve ser feita na sede
→ item depende da disponibilidade em estoque
```

---

## 5. Resgate do brinde

O resgate não deve ser modelado agora como cupom online.

Regra atual:

```txt
resgate presencial na sede
sujeito à disponibilidade do item em estoque
```

O sistema deve conseguir marcar o brinde como:

```txt
disponível
resgatado
cancelado
expirado, se uma regra futura definir expiração
```

---

## 6. Código para loja online

A geração de código para compra no site/loja online fica fora de escopo por enquanto.

Não criar nesta fase:

```txt
codigo_cupom
cupom_online
integracao_loja_online
```

Esse tema será estudado futuramente.

---

## 7. Implicação para a segunda migration

A segunda migration deve evitar nomes genéricos demais como se todo benefício fosse um cupom digital.

Recomendação de modelagem:

```txt
planos_associacao
  - adicionar codigo_plano
  - adicionar percentual_desconto_loja
  - adicionar mensalidades_para_brinde
  - adicionar descricao_brinde

cobrancas
  - controlar mensalidades pagas
  - controlar inadimplência e janela de fidelidade

fidelidade_movimentos
  - controlar sequência/consecutividade
  - registrar pagamento contado, reversão e zeragem

brindes_fidelidade_socio
  - controlar brinde liberado para o sócio
  - status: available, redeemed, cancelled, expired
```

---

## 8. Fora do escopo nesta fase

```txt
carteirinha digital
QR Code
cupom para loja online
controle de estoque real
sistema de gerenciamento/backoffice
integração com gateway financeiro real
```

O controle de estoque e a confirmação operacional do resgate serão melhor definidos quando o sistema de gerenciamento for modelado.
