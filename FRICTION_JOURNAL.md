# Friction Journal — Agent Keyring GCP Setup

> Raw material for the Digital Analytics Seidrbook (S-08). Every delta between
> training data / official docs and what the GCP console actually does.
> Append-only. Date and step each entry.

---

## 2026-08-29 — S-01: GCP Project Setup (Magistrate, console)

### F-001: API search ranking buries exact matches
**Step:** Enable Analytics Data API
**Expected:** Searching "Analytics Data" surfaces the exact match first
**Actual:** Three similarly-named APIs appear (Google Analytics Admin, Google Analytics,
Analytics Data API). The exact match is not at the top, even with a direct search.
**Impact:** User enables the wrong API and doesn't know until the adapter fails.

### F-002: IAP surfaces alongside service accounts
**Step:** Create a service account
**Expected:** IAM & Admin > Service Accounts is the clear path
**Actual:** IAP (Identity-Aware Proxy) appears in the same navigation neighborhood.
IAP is for protecting web apps with Google sign-in — completely different purpose,
but a user following "create an account for access control" could land there.
**Impact:** Confusion between machine identity (SA) and web auth (IAP). Wrong tool entirely.

### F-003: SA creation dumps you at the list, not the detail page
**Step:** Click "Create" after filling in service account details
**Expected:** Land on the new service account's detail page (to create a key)
**Actual:** Redirected to the service account list. New SA is at the bottom, below the fold.
**Impact:** User thinks creation failed, or can't find the SA to create a key. Requires
scrolling on a window that doesn't obviously scroll.

### F-004: "Grant access" step looks optional during SA creation
**Step:** The multi-step SA creation wizard includes a "Grant this service account
access to project" panel
**Expected:** Clear indication that skipping this means the SA has no permissions
**Actual:** The step looks like an optional extra. Skipping it creates a SA with zero roles.
**Impact:** SA exists but can't access Secret Manager. Error surfaces later ("permission denied")
with no connection to the skipped step.

### F-005: Key download uses opaque naming
**Step:** Keys tab > Add Key > Create new key > JSON
**Expected:** Meaningful filename or a prompt to name the download
**Actual:** Downloaded as `project-id-hexhash.json` (e.g., `coreforged-city-ec36841bd162.json`).
No indication of what the key is for, which SA it belongs to, or what role it has.
**Impact:** In a `.secrets/` directory with 30+ files, the key is indistinguishable from
other JSON credentials without opening it. User must rename manually for traceability.
