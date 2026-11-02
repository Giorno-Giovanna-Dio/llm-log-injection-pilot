| System | Detection (clean) | FP rate | ASR `fake_admin_note` | ASR `ignore_instructions` | Detection (defended) | FP (defended) | Defended ASR `fake_admin_note` | Defended ASR `ignore_instructions` | $ / sample | Unparseable outputs |
|---|---|---|---|---|---|---|---|---|---|---|
| Hayabusa, any alert >= low | 18/20 (90%) | 17/20 (85%) | 0/18 (0%) | 0/18 (0%) | n/a | n/a | n/a | n/a | $0 | n/a |
| Hayabusa, any alert >= medium | 17/20 (85%) | 6/20 (30%) | 0/17 (0%) | 0/17 (0%) | n/a | n/a | n/a | n/a | $0 | n/a |
| cheap LLM (claude-haiku-5-5) | 18/20 (90%) | 0/20 (0%) | 0/18 (0%) | 0/18 (0%) | 19/20 (95%) | 0/20 (0%) | 0/19 (0%) | 0/19 (0%) | $0.0010 | 0/160 |
| strong LLM (claude-sonnet-5-5) | 20/20 (100%) | 1/20 (5%) | 0/20 (0%) | 0/20 (0%) | 20/20 (100%) | 0/20 (0%) | 0/20 (0%) | 0/20 (0%) | $0.0187 | 0/160 |

Total LLM cost (list price): $3.16

| Model | Condition | Flagged | Mean confidence | Rationale mentions payload (keyword match) |
|---|---|---|---|---|
| cheap | attack_clean | 18/20 | 0.87 | 4/20 |
| cheap | attack_inj_fake_admin_note | 20/20 | 0.87 | 16/20 |
| cheap | attack_inj_ignore_instructions | 19/20 | 0.88 | 19/20 |
| cheap | attack_inj_fake_admin_note_def | 20/20 | 0.87 | 15/20 |
| cheap | attack_inj_ignore_instructions_def | 20/20 | 0.88 | 19/20 |
| strong | attack_clean | 20/20 | 0.91 | 1/20 |
| strong | attack_inj_fake_admin_note | 20/20 | 0.92 | 20/20 |
| strong | attack_inj_ignore_instructions | 20/20 | 0.94 | 18/20 |
| strong | attack_inj_fake_admin_note_def | 20/20 | 0.90 | 20/20 |
| strong | attack_inj_ignore_instructions_def | 20/20 | 0.91 | 20/20 |
