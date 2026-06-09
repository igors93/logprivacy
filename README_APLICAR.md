# Correção 01 — Authorization Bearer/Basic

Este pacote contém somente os arquivos que devem ser mesclados na raiz do repositório.

Arquivos alterados:

- `src/logprivacy/rules/credential.py`
- `tests/rules/test_credential_rule.py`

A correção garante que:

- `Authorization: Bearer <token>` resulte em `Authorization: Bearer [TOKEN]`;
- `Authorization: Basic <credencial>` resulte em `Authorization: Basic [SECRET]`;
- o token real não sobreviva à resolução de regras sobrepostas;
- campos posteriores da linha de log sejam preservados;
- atribuições entre aspas funcionem;
- as estratégias `partial` e `hash` sejam aplicadas apenas ao valor secreto.

Depois de mesclar, execute:

```bash
./scripts/ci.sh
```
