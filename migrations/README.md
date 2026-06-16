# Migrations — Savoia API

Este diretório contém migrations SQL executáveis pelo script simples `scripts/runMigration.js`.

## Como executar uma migration específica

```powershell
npm run migrate -- migrations/202606151_member_core.sql
```

## Migration inicial de sócios

### Executar

```powershell
npm run migrate:member-core
```

### Rollback

Atenção: remove tabelas e dados criados pela migration.

```powershell
npm run migrate:member-core:down
```

### Arquivos

```txt
202606151_member_core.sql
202606151_member_core.down.sql
```

Escopo:

```txt
socios_legado
planos_associacao
socios
auditoria_socio
```

## Migration de pagamentos e fidelidade

### Executar

```powershell
npm run migrate:member-finance-loyalty
```

### Rollback

Atenção: remove tabelas e dados criados pela migration.

```powershell
npm run migrate:member-finance-loyalty:down
```

### Arquivos

```txt
202606162_member_finance_loyalty.sql
202606162_member_finance_loyalty.down.sql
```

Escopo:

```txt
planos_associacao: complementos e planos reais
metodos_pagamento
assinaturas
cobrancas
fidelidade_movimentos
brindes_fidelidade_socio
```

Fora do escopo:

```txt
carteirinhas
QR Code
cupom para loja online
controle de estoque real
importação de planilha
sistema de gerenciamento/backoffice
integração com gateway financeiro real
```

## Observações

- O runner executa o SQL dentro de uma transação.
- O SQL não deve conter `BEGIN` ou `COMMIT` próprios.
- O banco usado é o mesmo configurado nas variáveis `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASS` ou equivalentes `PG*`.
- Em ambiente local, o usuário do banco precisa ter permissão de `CREATE` no schema `public`.
