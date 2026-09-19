---
name: debugging
description: Performs systematic root-cause debugging using evidence, reproduction, isolation, hypothesis testing, targeted fixes, and verification.
---

# Systematic Debugging

Never randomly change code.

Use:

OBSERVE
→ REPRODUCE
→ ISOLATE
→ HYPOTHESIZE
→ VERIFY
→ FIX ROOT CAUSE
→ TEST
→ REVIEW

Inspect:

- exact error
- logs
- stack traces
- browser console
- network requests
- database errors
- relevant code

Never assume the first plausible explanation is correct.

A hypothesis must be verified before treating it as the root cause.

Prefer the smallest root-cause fix.

After fixing:

- run relevant tests
- check related functionality
- check regression risk

Never claim a bug is fixed without verification evidence.
