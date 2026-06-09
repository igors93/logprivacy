# Correção 02 — representações seguras

Base: `969cbc1b917de911642841bdf7f743c19f849f2e`

Mescle o conteúdo deste pacote na raiz do repositório.

Arquivos alterados:

- `src/logprivacy/result.py`
- `src/logprivacy/audit.py`
- `tests/test_safe_representations.py`

A correção garante que:

- `repr()` e `str()` de `Finding` não revelem `matched`, `metadata` ou o valor mascarado;
- `repr()` e `str()` de `AuditReport` mostrem somente resumo seguro;
- `repr()` e `str()` de `RedactionResult` não revelem o original nem o conteúdo limpo;
- `Finding.to_dict()` exclua match e metadata por padrão;
- detalhes sensíveis continuem acessíveis somente com opt-in explícito.

Validação recomendada depois da mesclagem:

```bash
python3 -m pytest tests/test_safe_representations.py -vv
./scripts/ci.sh
```

Commit sugerido:

```text
Harden safe representations for audit results
```
