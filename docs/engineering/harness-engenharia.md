# Harness de engenharia — APP Savóia

Este é o guia operacional de desenvolvimento com agentes. Substitui, neste repositório, as recomendações genéricas do antigo harness do projeto. Não descreve recursos como já implementados: confirme o código e os scripts da branch atual.

Leia também as [instruções do repositório](../../AGENTS.md) e o [guia de adoção](adocao-codex.md).

## Escopo e simplicidade

- Diferencie explicar, diagnosticar, revisar e implementar. Um diagnóstico não autoriza correções; uma revisão não autoriza reescrita.
- Antes de mudar, identifique o fluxo executado, o contrato afetado e a menor alteração suficiente. Preserve mudanças preexistentes.
- Aplique a abordagem Ponytail: reutilize código adequado, recursos nativos e dependências existentes antes de acrescentar soluções. Legibilidade e correção prevalecem sobre quantidade de linhas.
- Não adicione ORM, framework, camada de repositório, injeção de dependências, cache, fila, Docker ou migração de linguagem sem necessidade demonstrada e compatível com o pedido.
- Não remova autenticação, autorização, validação, locks, transações, auditoria necessária, tratamento de falhas ou acessibilidade para simplificar.
- Descobrir uma falha fora do escopo exige relatá-la; não amplia automaticamente a tarefa.

## Configuração e segurança

- Segredos e diferenças reais entre ambientes pertencem à configuração apropriada. Constantes técnicas e nomes de tabelas não precisam virar variáveis de ambiente.
- Parâmetros de negócio já fornecidos pelo banco/API não devem ser duplicados no cliente.
- Nova variável ou dependência requer justificativa, impacto e documentação dentro do escopo autorizado; não é requisito de toda tarefa.
- Nunca publique senhas, tokens, OTPs, credenciais, CPF completo ou dados reais em logs, testes, respostas, issues ou PRs. Use dados sintéticos e saneie evidências.
- Queries usam parâmetros; permissões são verificadas no servidor, não apenas na interface.
- Transações PostgreSQL usam uma única conexão do início ao fim. Não use chamadas independentes ao pool para simular uma transação.
- Em testes e ferramentas, confirme explicitamente o destino do banco. Não rode migrations, rollback, limpeza ou fixtures contra produção.

## Verificação proporcional e TDD

Para uma mudança de comportamento:

1. Defina critérios de aceite e a interface observável a testar, junto ao usuário quando houver escolhas relevantes.
2. Reutilize o executor de testes existente. Se não existir, exponha a lacuna e combine a infraestrutura mínima antes de prometer cobertura.
3. Em TDD, execute um teste e confirme que falha pelo comportamento ausente, não por erro de configuração; implemente o mínimo para passar e avance um comportamento por vez.
4. Verifique casos de falha e regressões relevantes. Testes de locks, unicidade e rollback precisam de PostgreSQL descartável real; mocks não provam essas garantias.
5. Execute os comandos pertinentes disponíveis e informe resultado, limitações e verificações não executadas.

Ao adicionar testes de caracterização a comportamento existente, um teste inicialmente verde é válido; não o apresente como evidência de um ciclo TDD vermelho-verde.

Para documentação, verifique links e coerência com o código. Para UI, inclua carregamento, erro, vazio, sucesso, acessibilidade e smoke test nas plataformas disponíveis. Não afirme validação em iOS/Android sem executá-la.

A skill externa de TDD privilegia interfaces públicas. Para invariantes de persistência sem endpoint de leitura, combine explicitamente a verificação de estado no banco de teste; não crie endpoints de produção só para satisfazer uma convenção de teste.

## Revisão e entrega

- Revise correção e segurança, depois aderência ao escopo e complexidade dispensável. Ponytail não substitui revisão de bugs.
- Inspecione o diff completo: commits da branch, mudanças staged, unstaged e arquivos novos relevantes. Uma comparação entre commits não cobre arquivos ainda não commitados.
- Não execute commits, push, abertura de PR ou merge apenas porque uma skill pede; respeite a autorização da tarefa. Quando a entrega for PR, use uma branch própria `codex/`; não faça merge sem pedido.
- Relate o que mudou, o que foi testado e pendências reais. Não declare testes aprovados quando não há executor ou acesso ao ambiente.
- Preserve somente documentação útil e atual. Atualize a fonte existente; evite glossários, ADRs e históricos duplicados sem uma decisão duradoura que os justifique.
- Handoff é contexto de trabalho, não nova fonte de verdade do domínio. Referencie código, documentos e commits; não copie segredos nem dados pessoais.

## Compatibilidade entre instruções

Skills externas são procedimentos auxiliares. Elas não autorizam alterações de negócio, novos serviços, publicação ou refatorações fora do pedido. Não renomeie conceitos do Savóia nem arquivos existentes para adequá-los ao vocabulário de uma biblioteca de skills.

As regras de domínio são critérios a preservar, não prova de que todo código legado já as cumpre. Se código e regra divergirem, mostre a evidência e trate a correção conforme o escopo.
