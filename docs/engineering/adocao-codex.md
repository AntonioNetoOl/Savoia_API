# Adoção de Codex, Ponytail e TDD

## O que está versionado e o que ainda falta

Este repositório contém `AGENTS.md`, o [harness](harness-engenharia.md) e uma skill Savóia em `.agents/skills/`. Esses arquivos são instruções, não verificações automáticas.

Ponytail e as skills do AIHero não são instalados por esta documentação. Ela também não adiciona executor de testes, CI, variáveis de ambiente ou dependências da aplicação.

## 1. Abrir o checkout correto

Depois do merge da PR, atualize seu checkout sem descartar alterações locais e abra uma nova tarefa Codex na raiz do repositório. Não use apenas o espelho de documentos do projeto ChatGPT.

Peça: "Liste as instruções carregadas e confirme se a skill Savóia deste repositório está disponível. Não altere arquivos."

O Codex descobre skills em `.agents/skills/`. Use o seletor de skills ou mencione `$savoia-backend-change` na API e `$savoia-mobile-change` no app. Se não aparecerem, reinicie o Codex e confira a pasta/branch aberta. Instruções globais ou `AGENTS.override.md` podem interferir; inspecione antes de mudar essas configurações.

## 2. Instalar e verificar Ponytail

No terminal do seu computador, confirme:

```powershell
node --version
codex --version
codex plugin --help
```

Se a CLI Codex não estiver disponível ou não oferecer plugins, siga a instalação/atualização oficial antes de continuar.

Após revisar a origem do plugin, o procedimento publicado pelo mantenedor é:

```powershell
codex plugin marketplace add DietrichGebert/ponytail
codex plugin add ponytail@ponytail
```

Abra a CLI `codex`, consulte `/hooks`, revise os comandos dos hooks e autorize somente os que reconhecer. Reinicie o aplicativo desktop e abra uma nova tarefa. Node precisa estar acessível também ao ambiente que executa os hooks.

Selecione a skill `ponytail` e solicite o modo `full`, padrão recomendado para começar. Confirme o modo informado; estar instalado não comprova ativação. O README do plugin exemplifica `@ponytail-review` no Codex; a documentação oficial também oferece invocação explícita de skills com `$`. Prefira o item que o seletor da sua versão apresentar.

Use `ponytail-review` para revisar o diff da tarefa. Reserve `ponytail-audit` para uma auditoria expressamente solicitada. Não é necessário criar variável de ambiente da aplicação para utilizar o modo padrão.

Se a ativação falhar, confira Node, confiança dos hooks e reinicialização. Não desative sandbox ou permissões para contornar o problema. As instruções locais continuam úteis mesmo sem o plugin, mas não equivalem à sua ativação.

## 3. Adotar TDD e a referência de design

Na raiz de cada checkout, em uma branch de configuração, revise a origem e execute:

```powershell
npx skills@latest add mattpocock/skills --skill=codebase-design
npx skills@latest add mattpocock/skills --skill=tdd
```

No instalador, escolha Codex e escopo do projeto. Confira os arquivos criados, inclusive arquivos de lock ou links simbólicos, antes de commitá-los; não instale outra cópia global com o mesmo nome.

`codebase-design` é uma referência consultada por `tdd` quando a interface de teste precisa ser discutida, não uma dependência npm da aplicação. Preserve os arquivos auxiliares que o instalador traz. O par pode ser usado sem configurar um issue tracker; o setup completo da coleção só será necessário se adotarmos seus fluxos de planejamento/tracker.

Peça ao Codex: "Confirme a disponibilidade de tdd e codebase-design, leia o AGENTS.md e proponha as interfaces que vamos testar. Aguarde minha confirmação antes de escrever testes."

O instalador usa a versão disponível no momento. Revise o diff das atualizações antes de adotá-las; não atualize automaticamente as regras de toda a equipe.

## 4. Preparar testes reais em uma tarefa própria

Na base consultada para este guia, os dois projetos não possuem script `test`. Instalar uma skill não cria a suíte.

- Backend: avaliar primeiro o executor nativo da versão Node utilizada; definir fixtures sintéticas e PostgreSQL isolado para testes de associação, rollback e concorrência. As migrations de sócios dependem de tabelas anteriores: confira [as instruções de banco da API](https://github.com/AntonioNetoOl/Savoia_API/blob/main/migrations/README.md), sem assumir que um banco vazio já é reproduzível.
- Mobile: escolher um executor compatível com as versões Expo/React Native do projeto, testar componentes e integração no limite HTTP, além de smoke test no dispositivo disponível.
- Em ambos: acordar scripts e dependências de desenvolvimento, registrar o comando reproduzível e só então adicionar CI. Não introduzir checkout, gateway, novos estados de negócio ou migrations de produção para viabilizar a suíte.

Primeiros critérios sugeridos: vínculo único, repetição idempotente da mesma solicitação, rollback se auditoria falhar, ausência de cobrança/ativação no POST e feedback correto no app. A suíte pode exigir etapas diferentes; não finja que todos já estão cobertos.

## 5. Trabalhar e revisar

Exemplo backend:

```text
Use $savoia-backend-change e $tdd para a mudança descrita abaixo.
Leia o AGENTS.md, preserve o contrato atual e proponha primeiro
a interface observável e os critérios de aceite.
Não amplie o escopo nem crie pagamentos.
[Descreva a mudança.]
```

Exemplo mobile:

```text
Use $savoia-mobile-change para integrar o fluxo aprovado.
Reutilize o cliente HTTP e a navegação existentes.
Diferencie carregamento, erro e estado associativo.
Se a infraestrutura de testes estiver pronta, use $tdd.
Não simule ativação ou pagamento.
```

Revise o comportamento e o diff completo antes de solicitar `ponytail-review`. Se instalar `code-review`, dê uma base explícita e critérios de aceite; confira separadamente mudanças não commitadas. Não trate essa skill como auditoria de segurança. Corrija os achados relevantes antes de finalizar.

`handoff` e `diagnosing-bugs` são opcionais. Use o primeiro para transferir trabalho, preservando o arquivo fora de diretório temporário quando necessário. Use o segundo em defeitos difíceis, com dados saneados e autorização explícita caso também queira correção. Não é necessário instalar a coleção inteira ou `implement` para começar.

## 6. Tornar verificações obrigatórias

Em tarefa separada, rode a suíte no CI em toda PR, observe uma execução real e só então configure os checks correspondentes como obrigatórios na proteção da branch. Isso exige permissão administrativa. Não existem garantias automáticas apenas por adicionar Markdown.

## Fontes

- [Codex: skills e descoberta local](https://learn.chatgpt.com/docs/build-skills)
- [Codex: instruções AGENTS.md](https://learn.chatgpt.com/docs/agent-configuration/agents-md)
- [Ponytail: instalação e comandos](https://github.com/DietrichGebert/ponytail)
- [AIHero: TDD](https://www.aihero.dev/skills-tdd)
- [Código da skill TDD](https://github.com/mattpocock/skills/blob/main/skills/engineering/tdd/SKILL.md)
- [Coleção de skills e instalação](https://github.com/mattpocock/skills)
