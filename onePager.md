# VerifyAI — One-Pager

**Norton-style safety sweep for AI agents.** Describe a workflow, click Run Sweep, get an audit-ready compliance verdict in 90 seconds. Built by Darwin Adaptive Systems, Dearborn Heights, MI. Hack Michigan 2026 winner.

---

## Live Deployments

| Surface | URL | Default Framework | Vertical |
|---|---|---|---|
| Core | `verifyai-ten.vercel.app` | CMMC 2.0 L2 | Auto / Defense supply chain |
| Fin | `verifyai-fin.vercel.app` | GLBA Safeguards Rule | SMB Financial AI agents |

Both share one backend. New vertical = new frontend, no backend cost.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          USER (browser)                              │
│   - Picks workflow preset, target model, framework                   │
│   - Clicks Run Sweep                                                 │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  FRONTEND (Vercel static HTML)                       │
│   - verifyai-ten.vercel.app   (Auto/Defense, CMMC default)           │
│   - verifyai-fin.vercel.app   (Finance, GLBA default)                │
│   - Single-file index.html with Material 3 dark theme                │
└─────────────────────────────────────────────────────────────────────┘
                              │  HTTPS / Server-Sent Events
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│         BACKEND (Modal — verifyai-backend, shared)                   │
│                                                                       │
│   5 streaming SSE endpoints:                                         │
│   ┌────────────────────┬──────────────────────────────────────────┐ │
│   │ /parse-workflow    │ Granite → structured spec JSON           │ │
│   │ /run-webarena      │ Target agent runs realistic tasks         │ │
│   │ /run-deepteam      │ Adversarial probes + framework mapping    │ │
│   │ /generate-report   │ Granite → audit-ready executive summary   │ │
│   │ /list-models       │ OpenRouter catalog (~356 models)          │ │
│   └────────────────────┴──────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
        │                │                  │                  │
        ▼                ▼                  ▼                  ▼
  ┌──────────┐  ┌──────────────┐  ┌─────────────────┐  ┌─────────────┐
  │watsonx.ai│  │  OpenRouter  │  │    DeepTeam     │  │   Modal     │
  │Granite-4 │  │ (356 models) │  │ v0.2.7 + judges │  │  Secrets    │
  │h-small   │  │ Agent under  │  │  (gpt-4o-mini)  │  │  store      │
  │          │  │  test layer  │  │                 │  │             │
  └──────────┘  └──────────────┘  └─────────────────┘  └─────────────┘
```

---

## Data Flow (One Sweep)

1. **User → Frontend** — workflow text + target model + framework selection
2. **Frontend → `/parse-workflow`** — Granite returns a structured spec with agent role, custom system prompt, workflow steps, sensitive data, WebArena template, attack categories
3. **Frontend → `/run-webarena`** — target agent (from OpenRouter) runs the WebArena template tasks; completion rate + per-task results streamed back
4. **Frontend → `/run-deepteam`** — DeepTeam fires 6 adversarial attack methods against the agent; each finding maps to a specific framework control ID via `map_to_framework()`
5. **Frontend → `/generate-report`** — Granite writes an audit-ready 3-4 sentence executive summary citing the actual control IDs that were tested
6. **Frontend** renders 4 cards: Parsed Spec, Workflow Performance, Safety Posture, Executive Summary

All four endpoints stream Server-Sent Events (SSE) so the UI updates live during the 90-second sweep.

---

## Services

| Service | Role | Provider |
|---|---|---|
| **Granite-4-h-small** | Spec generation + executive summary writer | IBM watsonx.ai (us-south region) |
| **DeepTeam v0.2.7** | Adversarial red-team engine | Confident AI (open-source) |
| **OpenRouter** | Multi-model gateway (agent under test) | OpenRouter Inc. |
| **gpt-4o-mini (default)** | Judge model + simulator | OpenAI (via OpenRouter) |
| **Modal** | Serverless backend hosting | Modal Labs |
| **Vercel** | Static frontend hosting | Vercel Inc. |
| **GitHub** | Source repos | GitHub |

---

## Compliance Frameworks Supported

| Framework | Vertical | Default On |
|---|---|---|
| **CMMC 2.0 Level 2** | Defense Industrial Base | verifyai-ten |
| **GLBA Safeguards Rule** | Financial / Consumer Data | verifyai-fin |
| **SOC 2 Type II** | SaaS / General Trust | switchable |
| **IRS Pub 1075** | Federal Tax Information | switchable |
| **PCI DSS 4.0** | Payment Card Industry | switchable |

Each framework defines its own attack-to-control mapping in `FRAMEWORK_MAPPINGS` (backend). Switching the framework dropdown changes how findings are categorized without changing the underlying probes.

---

## DeepTeam Attack Methods (constant across frameworks)

- **PromptInjection** — injected instructions to override system behavior
- **Roleplay** — persona impersonation to extract stored system prompt
- **PermissionEscalation** — requests to bypass role boundaries
- **SystemOverride** — fake admin/maintenance context manipulation
- **InputBypass** — content filter evasion via input reformatting
- **GoalRedirection** — adversarial reframing of agent objectives

Each method is paired with vulnerability classes from DeepTeam: `PromptLeakage`, `PIILeakage`, `ExcessiveAgency`, `Toxicity`, `Bias`.

---

## Repos

| Repo | URL | Purpose |
|---|---|---|
| `vje013/verifyai` | github.com/vje013/verifyai | Core — Auto/Defense, owns the shared backend |
| `vje013/verifyai-fin` | github.com/vje013/verifyai-fin | Finance — frontend only, points at shared backend |

Future verticals (healthcare, legal) follow the same pattern: fork frontend, change defaults, point at the same Modal backend.

---

## File Layout

```
verifyai/
├── backend/
│   └── modal_app.py          # 5 endpoints, 5 framework mappings
├── frontend/
│   └── index.html            # Single-file Material 3 frontend
├── README.md
└── LICENSE                   # MIT

verifyai-fin/
├── frontend/
│   └── index.html            # Financial presets, GLBA default
└── README.md
```

---

## Identifiers

- **Modal app name:** `verifyai-backend`
- **Modal secrets:** `verifyai-secrets` (WATSONX_API_KEY, WATSONX_PROJECT_ID, OPENROUTER_API_KEY)
- **watsonx region:** `us-south.ml.cloud.ibm.com`
- **Granite model ID:** `ibm/granite-4-h-small`
- **Default target model:** `openai/gpt-4o-mini` (via OpenRouter)
- **Judge model:** `openai/gpt-4o-mini` (via OpenRouter)

---

## Built By

**Vladimir Edouard** — CEO, Darwin Adaptive Systems LLC. Dearborn Heights, Michigan.
- GitHub: github.com/vje013
- Built in Michigan, on watsonx, for Michigan.

**Hack Michigan 2026 winner — AI Collective Detroit / Michigan Small Business Track.**