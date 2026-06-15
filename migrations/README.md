# Migrations — Savoia API

Este diretório contém migrations SQL executáveis pelo script simples `scripts/runMigration.js`.

## Como executar uma migration específica

```powershell
npm run migrate -- migrations/202606151_member_core.sql
```

## Como executar a migration inicial de sócios

```powershell
npm run migrate:member-core
```

## Rollback da migration inicial de sócios

Atenção: remove tabelas e dados criados pela migration.

```powershell
npm run migrate:member-core:down
```

## Migration atual

```txt
202606151_member_core.sql
```

Escopo:

```txt
socios_legado
planos_associacao
socios
auditoria_socio
```

Fora do escopo desta primeira migration:

```txt
assinaturas
cobrancas
metodos_pagamento
fidelidade_movimentos
beneficios
beneficios_socio
carteirinhas
```

## Observações

- O runner executa o SQL dentro de uma transação.
- O SQL não deve conter `BEGIN` ou `COMMIT` próprios.
- O banco usado é o mesmo configurado nas variáveis `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASS` ou equivalentes `PG*`.
