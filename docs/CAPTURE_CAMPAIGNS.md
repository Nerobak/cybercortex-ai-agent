# Capture verification campaigns

Campaigns convert explicitly supplied authenticated HTTP captures into bounded
verification plans. Planning and scope checks are local. Active network
execution is disabled for Phase 2; `--execute --authorized` returns a
deterministic `plan_only` result with zero requests.

Example manifest:

```json
{
  "requests": [
    "verification_inputs/search-request.txt",
    "verification_inputs/download-request.txt"
  ],
  "default_scheme": "https",
  "enabled_families": ["sqli", "xss", "ssti", "ssrf", "traversal"],
  "request_budget": 40,
  "callback_url": "https://researcher-controlled-callback.example",
  "observed_callbacks": [],
  "traversal_canary": {
    "path": "cybercortex-canary.txt",
    "expected_marker": "CCX_CONTROLLED_CANARY"
  }
}
```

Review the offline plan first:

```bash
venv/bin/python campaign_cli.py --manifest verification_inputs/campaign.json
```

An execution request remains fail-closed:

```bash
venv/bin/python campaign_cli.py \
  --manifest verification_inputs/campaign.json \
  --execute \
  --authorized \
  --output-directory reports/campaign
```

The planner currently accepts GET captures only. It selects probe families by
parameter semantics; SQL injection and XSS may be considered for common search,
filter, and identifier inputs, while SSRF, traversal, command, and SSTI probes
require relevant parameter-name evidence. Missing callback or traversal-canary
configuration prevents those probe families from being scheduled.

Raw request files can contain local credentials, but planning output does not
include their values. Callback URLs and observations remain offline planning
inputs; Phase 2 does not send callback-capable traffic through this path.
