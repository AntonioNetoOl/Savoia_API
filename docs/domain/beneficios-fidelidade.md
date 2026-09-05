# Benefícios e brindes de fidelidade

Este documento registra as regras atuais de benefícios e brindes do domínio de sócios.

## Conceitos distintos

Benefício geral e brinde de fidelidade não são a mesma coisa:

- **benefício geral**: vantagem disponível ao sócio ativo, como o desconto nas lojas definido pelo plano;
- **brinde de fidelidade**: item liberado após o cumprimento da regra de mensalidades consecutivas pagas.

No schema atual, o desconto e a descrição do brinde ficam em `planos_associacao`. Um direito a brinde já liberado pertence a `brindes_fidelidade_socio`.

Não existem tabelas genéricas `beneficios` ou `beneficios_socio` nas migrations atuais.

## Planos vigentes

| Código | Plano | Mensalidade | Desconto nas lojas | Regra do brinde | Descrição cadastrada |
|---|---|---:|---:|---|---|
| `mutley` | Mutley | R$ 30,00 | 10% | 12 mensalidades consecutivas pagas | Boné, pescador ou touca |
| `dick` | Dick | R$ 50,00 | 15% | 12 mensalidades consecutivas pagas | Camiseta, regata ou bermuda |
| `vigarista` | Vigarista | R$ 75,00 | 20% | 12 mensalidades consecutivas pagas | Agasalho ou calça |

Os valores e descrições são cadastrados pela migration [`202606162_member_finance_loyalty.sql`](../../migrations/202606162_member_finance_loyalty.sql).

## Benefícios gerais

O acesso a benefícios gerais depende do estado associativo e das regras comerciais vigentes. No app, o estado elegível é `socio_ativo`.

O percentual de desconto nas lojas é definido pelo plano atual do sócio. A API já consegue expor esse percentual no resumo, mas não existe fluxo individual de resgate para benefícios gerais.

## Brinde de fidelidade

A regra vigente é:

```text
12 mensalidades consecutivas pagas
→ direito a brinde disponível
→ retirada presencial na sede
→ item sujeito à disponibilidade de estoque
```

Os estados aceitos para um registro em `brindes_fidelidade_socio` são:

```text
available
redeemed
cancelled
expired
```

A tabela representa o direito ao brinde e seu resgate. Ela não representa estoque físico nem cupom para loja online.

## Estrutura existente e automações pendentes

O banco já possui:

- `planos_associacao`, com preço, desconto e regra do brinde;
- `cobrancas`, para competências e estados de pagamento;
- `fidelidade_movimentos`, como histórico de contagem, reversão, ajuste, resgate e zeragem;
- `brindes_fidelidade_socio`, para os brindes liberados por ciclo.

Essa estrutura está preparada para o fluxo financeiro, mas ainda não existem automações completas para:

- processar pagamentos em gateway real;
- gerar e atualizar cobranças de ponta a ponta;
- contar automaticamente as 12 mensalidades consecutivas;
- liberar automaticamente o brinde;
- aplicar inadimplência e zeragem de fidelidade;
- controlar estoque ou confirmar a retirada por backoffice.

## Fora do escopo atual

- gateway e checkout reais;
- cupom online;
- controle real de estoque;
- backoffice;
- carteirinha digital e QR Code.

Os relacionamentos físicos dessas tabelas estão no [DER do domínio de sócios](./der-socios.md).


