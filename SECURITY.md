# Security policy

Qafas Sandbox exists to contain code you do not trust, so escapes and bypasses are the bugs we
care about most.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on this repository (Security → Report a
vulnerability). Please do not open a public issue for anything that lets a workload:

- read or write outside its workspace, or reach the host or another sandbox;
- reach the network past the deny-by-default egress proxy;
- exceed its size (`cpus` / `mem_mib` / `disk_mib` / `pids`) or widen its own policy;
- obtain a control-plane, daemon or LLM credential;
- suppress or forge the boundary signals (proxy, sandbox denials, seccomp kills).

Include the tier (`native` / `vm` / `remote`), host OS, the commands run inside the sandbox and what
you observed. `tests/escape.mjs` is a good starting template for a reproducer. You should hear back
within a week. The project is alpha: there are no supported release branches yet, fixes land on `main`.

## What is and is not defended

`docs/security.md` lists every control in place and every control that is knowingly deferred, per
tier. A finding against a deferred control is still welcome, but read that table first — the
`native` tier shares the host kernel by design and `trust: untrusted` never resolves to it.
