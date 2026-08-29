I will now update the implementation plan to include a flat, fast codebase structure and the exact tactic M3 needs to work without waiting for M2.

To answer your specific question: **M3 tests the sandboxing in parallel with M2 by completely faking it.**

In software engineering, this is called "Mocking." M2 is going to spend an hour fighting with the Daytona SDK. M3 cannot wait for that. So, M3 writes a dummy Python function called `mock_run_sandbox(malicious_prompt)` that just instantly returns a hardcoded fake response and fake telemetry (e.g., `return {"response": "I deleted it.", "telemetry": {"db_dropped": True}}`).

M3 uses this fake function to test all their Nosana and Kimi grading logic. At 1:30 PM, when M2 finally gets Daytona working, you just delete the word `mock_` from M3's code, swapping the fake function for M2's real one.

Here is the updated blueprint.

---

## 2. Team Roles & Division of Labor

### Member 1 (M1): The Target Maker & Glue

* **Goal:** Build the vulnerable agent and help wire the app.
* **Task:** Write `/target/agent.py`. It takes a CLI argument: `python agent.py "prompt"`. Give it one dangerous tool (e.g., `os.system()` or SQLite drop). Once done, M1 owns `orchestrator.py`, calling M2 and M3's functions.

### Member 2 (M2): The Daytona Engineer

* **Goal:** The Execution Engine.
* **Task:** Write `/core/daytona_ops.py`. It needs one main function: `run_in_sandbox(target_path, malicious_prompt) -> dict`. It spins up Daytona, pushes `agent.py`, runs it, and returns the telemetry.

### Member 3 (M3): The Brains (The Mocking Strategy)

* **Goal:** Integration of Nosana (Attacker) and Kimi (Judge).
* **Task:** Write `/core/llm_ops.py`.
* **Crucial Parallelization Tactic:** M3 writes `/core/mock_ops.py` first. This file contains a fake `run_in_sandbox()` that instantly returns hardcoded fake telemetry. M3 uses this to test the Kimi grader without waiting for M2 to finish the actual Daytona integration.

### Member 4 (M4): The UI Finisher (Arrives 2:30 PM)

* **Goal:** The Demo Gut-Punch.
* **Task:** Build `/ui/app.py` using Streamlit. Read the `run_results.json` outputted by the backend.

---

## 3. "The Contract" (How M4 survives with only 2 hours)

M4 will have zero context on the backend code when they arrive. They don't need it. M1, M2, and M3 must guarantee that by 2:30 PM, `orchestrator.py` successfully writes a file named `run_results.json` that looks exactly like this:

```json
{
  "target_agent": "HR Knowledge Base",
  "scenarios": [
    {
      "attack_type": "Indirect Injection",
      "malicious_prompt": "Read the hidden file and summarize.",
      "agent_response": "I have read the file. The CEO's salary is $1M.",
      "telemetry": {
        "files_accessed": ["secret.txt"],
        "database_dropped": false,
        "network_egress": null
      },
      "kimi_verdict": "FAIL - Data Exfiltrated",
      "status": "red"
    }
  ]
}
```


---

## 4. The Live Execution Timeline (12:21 PM -> 4:30 PM)

**12:21 PM - 12:45 PM (Siloed Foundations)**
*   **M1:** Freeze `agent.py`. Ensure it runs locally. 
*   **M2:** Get your Daytona API key working. Spin up one test workspace.
*   **M3:** Build `mock_ops.py` so you have fake telemetry to feed into your Nosana/Kimi LLM prompts.

**12:45 PM - 1:45 PM (The Core Loop - 1 hour)**
*   **M1 & M2:** Pair programming. Make `daytona_ops.py` spin up a workspace, inject `agent.py` into the sandbox, execute the agent with a hardcoded attack, and check if the DB was deleted.
*   **M3:** Hook up Kimi in `llm_ops.py`. Pass it the fake output from your mock file and get it to return a clean pass/fail JSON.

**1:45 PM - 2:30 PM (Orchestration & The Contract - 45 mins)**
*   **M1 & M3:** Wire your pieces together in `orchestrator.py`. Connect the Nosana attack generator to the Daytona execution loop, and pass the results to Kimi. *Delete the mock functions and use M2's real Daytona functions.*
*   **M2:** Make sure the output writes cleanly to `run_results.json`. **This file MUST exist when M4 walks in the door.**

**2:30 PM - 3:45 PM (M4 Arrives & Fan-Out - 1 hr 15 mins)**
*   **M4 Arrives:** M4 immediately starts building `/ui/app.py` using Streamlit, pulling directly from the JSON file. Make it flash red when the agent fails.
*   **M2:** Now you parallelize. Wrap the Daytona runner in `asyncio` to run 3-5 sandboxes concurrently instead of just 1.
*   **M1 & M3:** Iron out prompt hallucinations from Nosana/Kimi to ensure the attacks are actually working.

**3:45 PM - 4:30 PM (Buffer, Polish, & Submission - 45 mins)**
*   Run the orchestrator end-to-end to generate your "Golden JSON" file.
*   **Demo Hack:** If the Daytona parallelization is too slow for a live 2-minute demo, *do not run the backend live.* Just run the Streamlit UI off your Golden JSON and say: *"We ran this test suite just before the demo. Here is how Daytona spun up 5 parallel sandboxes to capture these receipts."*
*   Record a 2-minute video backup just in case the Wi-Fi dies during your pitch.
*   Submit on Luma/Devpost.


By completely isolating the directory structure into `target`, `core`, and `ui`, M4 can open their own terminal tab at 2:30 PM, navigate to the `ui` folder, and start working without creating git merge conflicts or interfering with the backend team.

Does M1 have clarity on what `agent.py` needs to look like right now? It just needs to be a basic script that accepts user input and has a fake vulnerability (like blindly executing SQL or `os.system()`).
