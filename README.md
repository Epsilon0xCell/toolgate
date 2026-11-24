# ToolGate

Author: Gavin Blacklock
Status: v0.1 working specification and prototype, 2026-11-23

ToolGate pins what an agent's tools are and enforces what they may do, before the model ever sees them.

ToolGate is specified as a local-first Model Context Protocol (MCP) capability firewall and signed tool-manifest gateway. It pins the exact tool definitions an agent is allowed to see, enforces per-task least-privilege scopes outside the model, and records every policy verdict, including denials, as an Acta receipt.

ToolGate is the enforcement layer of a three-layer programme. Institutio constitutes, ToolGate enforces, Acta proves. The combined v0.1 specification is included in full in this repository under `spec/`, because the section structure makes splitting it artificial.

## What exists, and what does not yet

This section states the current state plainly.

Exists now:

- `spec/`: the full combined v0.1 specification, including the ToolGate sections (Sections 3.4, 3.5, and 5) and the Standing enforcement sequence (Section 16.5).
- `python-prototype/toolgate/`: the Python ToolGate prototype module, clearly labelled as a prototype. It implements the in-process decision path: manifest pin checking, delegation and scope checking, revocation read from the receipt chain, budget checking, and Standing ceiling checking, emitting an Acta receipt for every allow and a reason-coded denial receipt, with a burn receipt, for every deny. It is in-process only.
- `python-prototype/acta/` and `python-prototype/institutio/`: the Python prototype packages the ToolGate prototype depends on, for receipts and for Standing computation.
- `python-prototype/tests/test_toolgate.py`: the prototype test module.
- `rust/crates/acta-core/`: the Rust `acta-core` crate, the receipt core that ToolGate depends on under the programme dependency rule (ToolGate depends on `acta-core`, which depends on the Acta specification). No Rust ToolGate crate exists yet.
- `fixtures/`: the fixtures relevant to ToolGate from the shared corpus: denial receipts, manifest mismatch, scope and delegation limits, expiry, Standing ceiling denials, and the kill family. The full 34-fixture corpus has its one home in the `acta` repository.
- `LICENSE`, `NO-RELICENSE-PLEDGE.md`, and `SECURITY.md`.

Specified but not yet built:

- The MCP proxy transport is NOT built. There is no MCP server or client proxy, no network transport, and no gateway process in this repository. The specification describes that proxy (Section 5.1); the prototype implements the decision path it will call, in-process.
- No dashboard, no hosted service, and no web interface exist, and none are in the v0.1 scope (Section 5.3).

No statement in this repository should be read as claiming that a working MCP gateway exists today. What exists is the specification, the decision-path prototype with its tests, the receipt core it depends on, and the fixtures that pin its expected verdicts.

## Licence

Code and specification text are licensed under the Apache License 2.0, with the written, irrevocable no-relicense pledge in `NO-RELICENSE-PLEDGE.md`. Trademarks are held personally by the author and are not licensed by the Apache License 2.0. Claims about this programme are limited to the receipt-anchored forms permitted by Annex A of the specification.
