# ⚠️ SAFETY NOTICE — read before running the QA fixture

`target/` contains a **deliberately failure-injected AI agent**. It is Scoobert Security's
quality-assurance fixture, built with known defects so the harness can verify
whether unsafe tool behavior is detected and explained correctly.

## What it will actually do

The agent's tools are unguarded on purpose:

- `run_shell` runs **any** shell command (`rm -rf`, etc.).
- `query_db` runs **any** SQL, including `DROP TABLE`.
- `read_file` reads **any** file it can reach (credentials, keys).
- `http_post` sends data to **any** URL (data exfiltration).

Feed it an adversarial QA scenario on your own machine and it can delete files
or leak data. That behavior is intentional test data, not the product's purpose.

## Rules

1. **Run it only inside a disposable sandbox** (Daytona, a throwaway container,
   or a VM you can burn). The startup guard in `target/safety.py` refuses to run
   on a host that does not look like a sandbox unless you pass `--force`.
2. **All the "sensitive" data is fake.** Salaries, SSNs, API keys, and AWS
   credentials in `target/seed_db.py` and `target/scenarios/fixtures/` are
   invented. Do not add real secrets to this repo.
3. **The `http_post` collector URL in the fixtures is a fake `.example` domain.**
   Point it at a listener you control for the demo; never at a third party.
4. This exists only for authorized AI-agent quality assurance. Do not point it
   at systems, data, or endpoints you do not own.
