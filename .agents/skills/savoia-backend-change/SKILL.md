---
name: savoia-backend-change
description: Implementar ou revisar mudanças na API Savóia com Express, pg e Joi, preservando contratos, transações e regras associativas. Usar em endpoints, serviços, autenticação ou persistência deste backend; não em tarefas exclusivamente mobile ou de instalação de ferramentas.
---

# Mudanças no backend Savóia

Leia [AGENTS.md](../../../AGENTS.md) e o [harness](../../../docs/engineering/harness-engenharia.md). As restrições permanentes estão neles; esta skill orienta o trabalho, sem autorizar mudanças além do pedido.

## Localizar o caminho executado

- Confirme repositório, branch, alterações existentes e o objetivo: revisão, diagnóstico ou implementação.
- Siga rota → middleware → validator → controller → serviço → banco apenas no fluxo afetado. Leia implementações existentes antes de criar novas abstrações.
- Para sócios, consulte [contratos](../../../docs/domain/socios-fluxos.md); para persistência, [DER](../../../docs/domain/der-socios.md) e [migrations](../../../migrations/README.md). Não carregue toda a documentação se a tarefa não precisar dela.
- Aponte divergências entre contrato, regra aprovada e runtime. Não corrija silenciosamente algo fora do escopo.

## Projetar a menor alteração

Descreva brevemente comportamento observável, arquivos afetados e riscos relevantes. Reutilize CommonJS, Joi, serviços e `withTx`; justifique dependências ou novas configurações quando realmente necessárias.

Se a tarefa tocar associação, examine identidade autenticada, plano disponível, estado elegível, repetição idempotente, lock, unicidade e auditoria dentro da mesma transação. Verifique também os efeitos que não podem ocorrer: assinatura, cobrança, pagamento e ativação.

Se tocar autenticação, diferencie finalidade/validade dos tokens, autorização e identidade da conta; não suponha que qualquer JWT assinado seja apropriado para qualquer operação.

## Verificar sem simular confiança

- Escolha critérios de aceite independentes da implementação e interfaces observáveis adequadas.
- Se TDD estiver disponível e couber no pedido, use a skill `tdd` após combinar as interfaces de teste. Se não estiver, siga um ciclo explícito de teste falhando → implementação mínima → teste passando; não instale ferramentas sem necessidade/autorização.
- Para caracterização de comportamento existente, aceite teste inicialmente verde e identifique-o como tal.
- Para associação, priorize conforme o diff: criação, reutilização, repetição, rejeições, rollback e concorrência. Use PostgreSQL isolado para garantias de banco, não mocks que apenas devolvem sucesso.
- Quando não houver executor/banco de teste, informe o bloqueio específico e as verificações alternativas realizadas. Nunca rode operações destrutivas contra banco real.
- Em revisão/diagnóstico somente, entregue achados e evidências sem aplicar correções.

## Fechar o trabalho

Revise o diff completo, remova apenas complexidade dispensável introduzida pela tarefa e atualize a documentação existente se o contrato tiver mudado com autorização. Resuma mudanças, comandos executados, resultados e limitações. A skill não cria commit, push, PR ou merge por iniciativa própria.
