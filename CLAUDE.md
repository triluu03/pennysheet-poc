# Pennysheet POC

A proof-of-concept personal finance application that aggregates bank account data using the [Enable Banking API](https://enablebanking.com/docs) and exposes it through a Flask web server.

## Stack

- **Backend:** Python / Flask
- **Banking data:** [Enable Banking API](https://enablebanking.com/docs)
- **Package manager:** `uv` — use this for all dependency changes (e.g. `uv add <package>`)

## Key Rules

- Never commit changes to git. The developer handles all commits manually.
- When adding new packages, always use `uv add <package>` (not pip, poetry, or conda).
