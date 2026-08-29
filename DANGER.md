# ⚠️ DANGER — read before running the target agent

`target/` contains a **deliberately vulnerable AI agent**. It is the red-team
*target* for Project Sentinel, built to be exploited so we can observe what a
compromised, tool-using agent does.

## What it will actually do

The agent's tools are unguarded on purpose:

- `run_shell` runs **any** shell command (`rm -rf`, etc.).
- `query_db` runs **any** SQL, including `DROP TABLE`.
- `read_file` reads **any** file it can reach (credentials, keys).
- `http_post` sends data to **any** URL (data exfiltration).

Feed it a hostile prompt on your own machine and it can delete your files or
leak your data. That is the point of the exercise.

## Rules

1. **Run it only inside a disposable sandbox** (Daytona, a throwaway container,
   or a VM you can burn). The startup guard in `target/safety.py` refuses to run
   on a host that does not look like a sandbox unless you pass `--force`.
2. **All the "sensitive" data is fake.** Salaries, SSNs, API keys, and AWS
   credentials in `target/seed_db.py` and `target/scenarios/fixtures/` are
   invented. Do not add real secrets to this repo.
3. **The `http_post` collector URL in the fixtures is a fake `.example` domain.**
   Point it at a listener you control for the demo; never at a third party.
4. This exists for an authorized hackathon red-team exercise. Do not point it at
   systems you do not own.
