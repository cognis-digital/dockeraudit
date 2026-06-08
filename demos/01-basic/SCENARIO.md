# Demo 01 — Basic Dockerfile audit

A realistic application `Dockerfile` that ships with multiple common
security/hygiene smells. Use it to see every renderer and the non-zero
exit behavior.

## The artifact

`Dockerfile` in this directory builds a Python web service but contains:

- `FROM python:latest` — mutable base tag (**DA002**)
- A hardcoded `API_KEY` in `ENV` and `DB_PASSWORD` in `ARG` (**DA003**, CRITICAL)
- `curl ... | sudo bash` pipe-to-shell install (**DA004**, **DA005**)
- `chmod -R 777 /app` world-writable perms (**DA006**)
- `ADD ./requirements.txt` where `COPY` suffices (**DA007**)
- `COPY . /app` copying the whole build context (**DA011**)
- `apt-get install` without cache cleanup (**DA009**)
- `EXPOSE 22` SSH in a container (**DA008**)
- No non-root `USER` (**DA001**, runs as root)
- No `HEALTHCHECK` (**DA010**)

## Run it

```bash
# Human-readable table (default)
python -m dockeraudit audit demos/01-basic/Dockerfile

# JSON for pipelines / CI
python -m dockeraudit audit demos/01-basic/Dockerfile --format json

# Shareable self-contained HTML UI report
python -m dockeraudit audit demos/01-basic/Dockerfile --format html -o report.html

# List all rules
python -m dockeraudit rules
```

The command exits non-zero because findings reach the default fail level
(`HIGH`). Lower the gate with `--fail-level CRITICAL` or raise it with
`--fail-level INFO` to tune CI strictness.

This is detection / triage only: dockeraudit reads the Dockerfile and reports
posture. It performs no network calls and takes no action against any system.
