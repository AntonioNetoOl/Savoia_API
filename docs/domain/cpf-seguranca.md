# Segurança de CPF — APP Savóia

Este documento registra opções e recomendação inicial para armazenamento e uso de CPF no domínio de Sócios.

---

## 1. Contexto

O CPF já é obrigatório no cadastro do app.

Ele também será o principal dado de conciliação entre `usuarios` e a futura tabela `socios_legado`.

Fluxo esperado:

```txt
usuario.cpf
→ normaliza CPF
→ busca em socios_legado
→ se encontrar, cria socios com tipo_origem = legacy_import
```

---

## 2. CPF pode ser armazenado?

Sim, CPF pode ser armazenado quando há finalidade legítima e necessidade operacional.

No APP Savóia, a finalidade é:

- identificar usuário;
- evitar duplicidade;
- vincular sócio legado;
- preservar número de sócio;
- permitir validação administrativa futura.

CPF não deve ser tratado como dado público. Ele deve ser tratado como dado pessoal identificador e protegido por controles técnicos e administrativos.

---

## 3. Opções técnicas

### Opção A — CPF em texto normalizado

Exemplo:

```txt
cpf = 12345678901
```

#### Vantagens

- Simples de implementar.
- Fácil de consultar.
- Fácil de debugar.
- Facilita importação da planilha legada.

#### Desvantagens

- Se o banco vazar, CPFs vazam diretamente.
- Aumenta impacto de incidente.
- Exige mais disciplina de acesso, logs, backups e ambiente.

#### Uso recomendado

Aceitável para MVP se houver:

- banco privado;
- conexão segura;
- controle de acesso;
- variáveis de ambiente protegidas;
- sem logs de CPF;
- sem exposição de CPF completo em frontend;
- backups protegidos.

---

### Opção B — Hash simples de CPF

Exemplo:

```txt
cpf_hash = sha256(cpf_normalizado)
```

#### Vantagens

- Não armazena CPF diretamente.
- Permite comparação exata.

#### Desvantagens

- CPF tem universo pequeno e previsível.
- Hash simples pode ser atacado por força bruta/dicionário.
- Não permite recuperar o CPF original.
- Não resolve todos os usos administrativos.

#### Uso recomendado

Não recomendado sozinho.

---

### Opção C — HMAC/peppered hash para busca

Exemplo conceitual:

```txt
cpf_lookup_hash = HMAC_SHA256(cpf_normalizado, CPF_PEPPER)
```

#### Vantagens

- Permite busca exata por CPF.
- Mais seguro que hash simples.
- O segredo (`CPF_PEPPER`) fica fora do banco, em variável de ambiente/secret manager.
- Se o banco vazar sem o segredo, fica muito mais difícil reconstruir CPFs.

#### Desvantagens

- Não permite recuperar CPF original.
- Exige gestão segura do segredo.
- Troca do segredo exige reprocessamento.

#### Uso recomendado

Recomendado para lookup automático.

---

### Opção D — Criptografia reversível

Exemplo conceitual:

```txt
cpf_encrypted = encrypt(cpf_normalizado, CPF_ENCRYPTION_KEY)
```

#### Vantagens

- Permite recuperar CPF quando houver necessidade administrativa legítima.
- Reduz exposição em caso de vazamento parcial do banco.
- Bom para backoffice futuro.

#### Desvantagens

- Exige gestão de chave.
- Código fica mais complexo.
- Se a chave vazar junto com o banco, perde parte da proteção.

#### Uso recomendado

Recomendado quando o backoffice precisar visualizar CPF completo.

---

### Opção E — Modelo combinado

Campos:

```txt
cpf_hash
cpf_encrypted
cpf_masked
```

Uso:

```txt
cpf_hash      → busca e vínculo automático
cpf_encrypted → recuperação administrativa controlada
cpf_masked    → exibição segura no app/backoffice
```

Exemplo de máscara:

```txt
***.***.***-01
```

#### Vantagens

- Melhor equilíbrio entre segurança e operação.
- Busca rápida por CPF sem abrir o dado.
- Exibição segura por padrão.
- Suporte a backoffice no futuro.

#### Desvantagens

- Mais implementação.
- Exige gestão de segredo/chave.

#### Uso recomendado

Recomendado como arquitetura alvo.

---

## 4. Recomendação para o APP Savóia

### MVP inicial

Para não travar o desenvolvimento, a recomendação é:

```txt
usuarios.cpf_normalizado
socios_legado.cpf_normalizado
socios_legado.cpf_hash
```

Com regras:

- CPF normalizado com apenas números;
- CPF completo nunca exibido no app;
- logs não devem registrar CPF completo;
- endpoint deve retornar CPF mascarado quando necessário;
- `cpf_hash` deve ser usado para vínculo automático quando a camada de segurança estiver pronta.

### Arquitetura alvo

Evoluir para:

```txt
cpf_hash
cpf_encrypted
cpf_masked
```

Busca por:

```txt
cpf_hash
```

Exibição por:

```txt
cpf_masked
```

Recuperação administrativa controlada por:

```txt
cpf_encrypted
```

---

## 5. Boas práticas obrigatórias

1. Nunca logar CPF completo.
2. Nunca retornar CPF completo para o app sem necessidade.
3. Exibir CPF apenas mascarado.
4. Limitar acesso administrativo a CPF completo.
5. Proteger backups do banco.
6. Proteger variáveis de ambiente e chaves.
7. Usar HTTPS em produção.
8. Usar conexão segura entre API e banco.
9. Auditar ações administrativas envolvendo dados pessoais.
10. Ter rotina futura para correção/exclusão conforme necessidade legal/operacional.

---

## 6. Impacto no vínculo legado

O vínculo automático por CPF deve operar assim:

```txt
cpf informado no cadastro
→ normaliza CPF
→ calcula cpf_hash
→ busca socios_legado.cpf_hash
→ se encontrar, cria socios com numero_socio herdado
```

Enquanto `cpf_hash` não estiver implementado, a busca pode usar `cpf_normalizado`, desde que o banco e os acessos estejam protegidos.

---

## 7. Decisão inicial

A decisão inicial é aceitar armazenamento de CPF normalizado no MVP, com controle de acesso e sem exposição no frontend, e projetar a evolução para modelo combinado com hash/HMAC e criptografia reversível.
