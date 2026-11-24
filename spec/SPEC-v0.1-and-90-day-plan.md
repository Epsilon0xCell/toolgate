# Acta, ToolGate, Institutio: Combined v0.1 Specification and 90-Day Plan

Author: Gavin Blacklock
Status: v0.1 working specification, founding document
Date: 2026-11-23
Licence: Apache License 2.0 for code and specification text (Section 13). Trademarks are held personally by the author and are not licensed by the Apache License 2.0.
Sources: synthesized from five research reports dated 2026-11-23 (Acta founding report; Acta and ToolGate programme report; firm-scale Constitution Layer report; instant fame and genius capability report, folded in at Section 7, Annex A, and conflict note 7 in Section 17; game-changing mechanism report, folded in at Section 16, the Section 7 amendment, and conflict note 8 in Section 17). Probability figures in this document are labelled speculation wherever they appear. They are disciplined judgement, not statistics.

## 1. The programme

### 1.1 One programme, three layers

This document specifies one programme with three layers. It is not three unrelated projects. Each layer has one job, one sentence, and one repository line of its own, and the layers compose in a fixed order: Institutio constitutes, ToolGate enforces, Acta proves.

| Layer | Job | One-liner |
|---|---|---|
| Acta | Evidence | Acta makes every AI-agent action leave a signed, replayable receipt: no receipt, no trust. |
| ToolGate | Enforcement | ToolGate pins what an agent's tools are and enforces what they may do, before the model ever sees them. |
| Institutio | Constitution | Institutio constitutes an agent organisation: a signed charter, delegated-authority manifests, budgets, and succession, with a replayable Acta receipt for every consequential action, on any model or framework. |

Programme line, for umbrella pages only and never as a product headline: Acta is the receipt. ToolGate is the gate. Institutio is the charter. Grants enforced, actions proven, organisations constituted.

### 1.2 What each layer is, in one paragraph

Acta is a local-first, framework-neutral receipt format, hash-chained ledger, command line tool, and offline verifier. A receipt binds who delegated an action, which agent and model acted, what capability scope was granted, what action was taken, what the result was, and what changed. Receipts are portable artifacts: they travel with the pull request, the commit, the dataset, the incident report, or the audit bundle they describe.

ToolGate is a local-first Model Context Protocol (MCP) capability firewall and signed tool-manifest gateway. It pins the exact tool definitions an agent is allowed to see, enforces per-task least-privilege scopes outside the model, and records every policy verdict, including denials, as an Acta receipt.

Institutio is an open standard and reference implementation for constituting an organisation of humans and agents. Its charter file is `institutio.json`. A charter declares the organisation's seats and roles, the authority each seat holds, the budgets it may spend, how the charter is amended, who succeeds whom, and how the whole organisation is halted. Every consequential action taken under a charter leaves an Acta receipt, so an Institutio organisation is auditable by a third party who trusts none of its members.

### 1.3 Why three layers and not one

A receipt without an authority model proves that something happened but not whether it was permitted. Authority without enforcement is a policy document nobody obeys. Enforcement without a constitution governs one tool session, not an organisation that outlives any session. The three layers close those three gaps for each other:

1. Institutio supplies the authority model: charters, seats, delegations, budgets, succession.
2. ToolGate supplies enforcement at the point of action: pinned tool definitions and granted scopes, checked before the model sees a tool.
3. Acta supplies the evidence: signed, hash-chained, replayable receipts that an independent verifier can check offline.

### 1.4 The builder premise

This plan is written for firm-scale execution, not solo execution. The founder, Gavin Blacklock, directs a firm of more than 10,000 agentic employees in named seats and is the sole human final authority. The binding constraints are therefore not typing speed or implementation labour. They are:

1. Founder verification bandwidth. Every specification decision, security sign-off, and external commitment funnels through one human. This is the critical path and is budgeted like capital.
2. Coherence and quality control. Agent labour produces inconsistency at the same scale it produces output, unless the canonical core is small and frozen early.
3. Adoption and legitimacy. External adoption, standards standing, and public trust attach to a named accountable human and cannot be manufactured by agent headcount.
4. Security of the workforce itself. A firm whose product is trust, run by agents, is a high-value supply-chain target. Section 12 treats the firm as its own first threat model.

Working numbers used throughout this plan, taken from the firm-scale research report and labelled there as inference: roughly 20 to 40 seats work on this programme, not the whole firm; agent parallelism multiplies shipped surface by roughly 3 to 5 times a solo build in 90 days, and multiplies decision speed by 1 times, that is, not at all; the core specification is frozen at about day 30.

### 1.5 The window

The standards window is dated, not rhetorical. The NIST AI Agent Standards Initiative launched on 2026-02-17. The EU AI Act Article 12 requires high-risk AI systems to automatically record events across their lifetime, and Articles 19 and 26 require providers and deployers to retain logs for at least six months; after the 2026 Digital Omnibus, those duties apply from 2027-12-02 for Annex III systems and 2028-08-02 for Annex I systems. The Act demands the capability and supplies no schema, no charter model, and no delegation semantics. Formats that exist, are implemented, and have foreign producers during 2026 and 2027 get cited. Formats that arrive after frameworks ship their own audit logs get ignored. Every release in this plan must name the obligation it satisfies.

## 2. Fixed decisions

The following decisions are made. Engineering seats implement them; they do not re-open them.

### 2.1 Dependency rule

Dependencies point in one direction only:

```text
institutio  depends on  acta (receipt format, as its evidence format)
toolgate    depends on  acta-core, which depends on the Acta specification
acta        depends on  nothing in this programme
```

1. ToolGate depends on `acta-core`. `acta-core` depends on the Acta specification.
2. Acta must never depend on ToolGate or on Institutio: no import, no optional dependency, no required field that only ToolGate or Institutio can produce.
3. Institutio depends on Acta receipts as its evidence format. Institutio does not extend the Acta wire format with required fields; Institutio data travels in its own predicate namespaces (Section 3.1).
4. Conformance test, mandatory in continuous integration: the full Acta test suite passes with the ToolGate and Institutio repositories deleted. If this test fails, the build fails.

### 2.2 Signing decision: DSSE-style typed envelopes, not canonical JSON

All signing in this programme uses an in-toto and DSSE style typed envelope over exact bytes. Signatures are computed over a Pre-Auth-Encoding (PAE) of the payload type and the exact payload bytes, following the DSSE protocol. Canonical-JSON signing is rejected for v0.1.

Reasoning, stated once and binding:

1. Canonicalisation forces every verifier to re-encode the payload before checking the signature. Any disagreement between the signer's encoder and the verifier's encoder, across languages, number formats, key ordering, or Unicode handling, produces a signature that fails on a genuine receipt or, worse, a disputed one.
2. The in-toto and DSSE design deliberately signs exact bytes inside a typed envelope for exactly this reason, and published analysis of agent-record formats criticises canonical-JSON signing on this point by name.
3. A receipt format whose entire purpose is third-party verification cannot carry a known signer and verifier disagreement class in its core operation.
4. Consequence for the format: the signed payload is an opaque byte string inside the envelope. Human-readable JSON is the payload encoding in v0.1, but verifiers hash and check the bytes as received, never a re-serialisation. Pretty-printing a signed payload invalidates it, and the tooling must say so.

### 2.3 Repositories and release cycles

1. Three repositories: `acta` (specification, `acta-core`, CLI, verifier), `toolgate` (gateway and proxy), `institutio` (charter specification, charter tooling, conformance suite for charters).
2. The shared attack-fixture corpus lives in the `acta` repository only, under `fixtures/`, with labels for the other layers. It has exactly one home.
3. Acta specification releases are slow and semantic-version strict, at most monthly, with a compatibility promise. ToolGate releases fast, up to weekly, and pins a supported Acta specification range (for v0.1: `acta-spec >=0.1 <0.2`). Institutio pins an Acta specification range the same way.
4. Backward compatibility rule, absolute: old receipts must verify forever. A verifier release that rejects a previously valid receipt is a critical defect, not a breaking change.
5. Releases are staggered, never in the same week across repositories, and are fully automated: continuous integration builds and signs release artifacts from version 0.1 onward.

### 2.4 Names

1. The evidence layer is Acta. The enforcement layer is ToolGate. The constitution layer is Institutio, Latin for an institution and for its founding instruction, after the precedent of Justinian's Institutes, the textbook that taught Roman law to every student who entered it.
2. An organisation's charter file is named `institutio.json`.
3. Naming caveat, recorded honestly: the name Institutio was collision-screened against live web search on 2026-11-23. The candidate names Mandatum, Mandata, Foedus, Statuta, Ordo, Charta, Civitas, Politeia, Pactum, and Organa were all found occupied in or near this space. Institutio surfaced no software or standard collision in that screening. A screening is not a trademark clearance. A formal trademark search, and filing in the founder's own name, remain required year-one acts (Section 13.3).
4. Acta's name availability was not trademark-checked in the underlying research. The same formal search in Section 13.3 covers all three names before any public launch claim is made about them.

## 3. Shared components: acta-core

Everything in this section is literally the same code and the same specification text across all three layers. There is one implementation of each item. Forking any of them per layer is a defect.

### 3.1 Receipt format and JSON Schema

1. The Acta specification defines the receipt format and publishes a JSON Schema for it. ToolGate and Institutio receipts are Acta receipts. Layer-specific data lives in namespaced predicates: `toolgate.*` for enforcement data, `institutio.*` for charter data. No layer-specific field may appear outside its namespace, and no namespaced field may be required by the core schema.
2. Core receipt fields, v0.1:
   - `receipt_version`: specification version that produced the receipt.
   - `receipt_id`: unique identifier for this receipt.
   - `timestamp`: time of the action, plus an optional external anchor reference (Section 3.7).
   - `delegator`: identity of the principal who delegated the action (key identifier, Section 3.7).
   - `agent`: agent identity, model name, and model version that acted.
   - `scope_granted`: the capability scope in force, expressed in the shared scope language (Section 3.3). This field records the exact scope value that enforcement checked.
   - `action`: tool or action name, and a hash of the arguments. Raw arguments may be included by local policy; the hash is always present.
   - `result_hash`: hash of the result or outcome.
   - `effects`: files and artifacts changed, external calls made, and sub-delegations created, each as hashes or references.
   - `verdict`: for enforcement receipts, the policy verdict record (Section 3.5).
   - `prior_receipt_hash`: hash of the previous receipt in the chain (Section 3.2).
   - `envelope`: the DSSE-style typed envelope and signature set (Section 2.2).
3. Receipts reference external evidence rather than replacing it: software build attestations (SLSA and in-toto), media provenance manifests (C2PA), model signing records (OpenSSF Model Signing), and telemetry trace identifiers (OpenTelemetry) may be cited by reference inside a receipt. Acta is the SLSA and in-toto of agent actions; it imports the neighbouring evidence, it does not compete with it.

### 3.2 Signing and hash-chain library

1. One library implements envelope signing, verification, and the hash chain. The Acta CLI, the offline verifier, ToolGate, and Institutio tooling all call it.
2. Each receipt carries the hash of the prior receipt, forming an append-only chain per ledger. A gap, a reordering, or a substituted receipt breaks verification at the point of tampering.
3. The local ledger is deliberately boring storage: an append-only local file, SQLite or JSONL. Local-first is a founding property, not a deployment option. No receipt requires a hosted service to create or to verify.
4. Signing levels, mirroring the SLSA levels pattern:
   - Level 1: a receipt exists and is hash-chained.
   - Level 2: the receipt is signed by the enforcement point (for example ToolGate), not by the acting agent itself.
   - Level 3: the enforcement point is isolated from the agent, so the agent cannot mint, alter, or suppress its own receipts.

### 3.3 Capability scope language

1. One grammar defines capability scopes: which tools, which resources, which operations, under which limits.
2. The scope value ToolGate enforces must be byte-identical to the scope value recorded in the receipt's `scope_granted` field. This is the single most important shared component in the programme. If the enforced scope and the recorded scope can differ, the receipt proves nothing.
3. Institutio authority manifests (Section 6) express seat authority in this same language. A charter grant, a ToolGate enforcement check, and an Acta receipt all carry the same scope bytes for the same grant.

### 3.4 Tool-manifest pinning format

1. A tool manifest lists a tool's name, description, input schema, and provider, as disclosed at approval time. The manifest format and its canonical hash (SHA-256 over the exact manifest bytes) are defined in the Acta specification as the subject of a receipt, following the in-toto pattern in which a subject is the digest of exact bytes.
2. Pinning works as follows: at approval, the manifest hash is recorded. At session start and at call time, the manifest is re-fetched or re-presented and its hash re-checked against the pin. A mismatch is a rug-pull or a silent edit, and the call does not proceed. This is the fix pattern for the class of attack in which a once-approved MCP configuration is silently edited afterwards (documented publicly as CVE-2025-54136, the Cursor MCPoison case).
3. Pinning alone catches definition drift and nothing else. Enforcement (Section 5) and receipts (Section 4) supply the rest: every call is tied to the exact definition that was disclosed for it.

### 3.5 Policy verdicts as receipts

1. Every ToolGate allow and every ToolGate deny produces an Acta receipt. The `verdict` predicate records the policy hash, the manifest hash, the scope checked, and the decision.
2. A denial with no receipt is an unprovable claim. Deny receipts are first-class evidence: they are how an organisation proves its gate worked on the day it mattered.
3. Denial receipts are a first-class receipt type, not an annotation on an allow receipt. Every denial receipt carries a reason code from the v0.1 set (`revoked`, `scope`, `manifest-mismatch`, `budget`, `standing-ceiling`), the attempted tool or action, the agent seat, and the delegation-manifest hash, hash-chained like any other receipt. The `standing-ceiling` code records a denial on Standing grounds under Section 16, and a denial receipt issued on that ground also carries the recomputed Standing ceiling that the attempt exceeded. A denial receipt without a reason code is non-conforming. This requirement is ticket T2 of the Provable Kill (Section 7.3) and is flagged there as the single most important addition in that section: without reason-coded denial receipts, a revocation proves only silence, and silence is stageable.
3. Institutio-level verdicts follow the same rule: a charter check that refuses an action because the seat lacks authority, or the budget is exhausted, produces a receipt recording the charter hash and the refusing rule.

### 3.6 Shared attack-fixture corpus

1. One corpus of attack fixtures is consumed by all three layers' test suites. A fixture is a triple: the attack input, the expected ToolGate or Institutio verdict, and the expected Acta receipt or verification result.
2. Version 0.1 ships at least 25 fixtures, covering at minimum:
   - Tool-poisoning descriptions that hide instructions inside tool metadata.
   - Rug-pulls: a tool definition that changes between approval and call.
   - Cross-server shadowing, in which one server redefines or intercepts another server's tool.
   - Scope-escalation attempts: an agent requesting or exercising more than its granted scope.
   - Receipt tampering: chain breaks, signature substitution, receipt replay, receipt suppression.
   - Charter attacks (Institutio): forged charters, delegation loops, a seat granting authority it does not hold, budget double-spend, succession hijack, and a revoked seat continuing to act.
   - The Provable Kill fixture family (Section 7.3, ticket T6): a rogue seat with a genuine delegation whose post-revocation attempts (direct action, action through a pre-revocation child sub-delegation, and replay of a previously valid authorisation) must each produce the expected reason-coded denial receipt, while unrelated seats produce valid continuity receipts in the same window.
3. Fixtures must be empirical, built from documented attack behaviour, not toy examples. The corpus accepts community contributions from v0.1 under a signed-template review process, so fixture writing never becomes a single-team bottleneck.

### 3.7 Key identity model

1. Principals, agents, seats, and enforcement points are identified by keys. Version 0.1 uses local Ed25519 keys. Short-lived, identity-provider-issued credentials in the Sigstore style are a documented later level, not a v0.1 dependency.
2. Root keys are held by the human founder, never by an agent seat. No agent in the firm holds a key that can sign a charter, amend a charter, or anchor a ledger.
3. External anchoring from day one: ledger heads are anchored outside the firm, for example in a public transparency log in the Sigstore Rekor style or by RFC 3161 trusted timestamping, so that the firm's own records cannot be quietly rewritten by anyone, including the firm.
4. Key separation, absolute: charter-signing keys, ToolGate enforcement signing keys, Acta test-vector keys, and release-signing keys are four different key sets, held and rotated separately. A compromise of one set must not compromise the others.
5. Every repository carries its own `SECURITY.md`. Incident communications name the affected component and the unaffected components explicitly. The architecture must make the following sentence sayable and true: the gateway failed to check the receipt; the receipt format verified correctly.

## 4. Acta v0.1 specification

### 4.1 Scope

Version 0.1 ships:

1. The receipt specification: one short normative document, the JSON Schema, a threat model, and at least 10 worked examples, in a public repository from week 1.
2. The `acta` CLI as a single binary: `init`, `log` (append a receipt), `verify` (check a chain and its signatures), `export` (produce a portable receipt bundle), and `replay` (replay-lite, Section 4.2).
3. The offline verifier: the same verification code as the CLI, packaged so a third party with no network access and no account can verify a bundle.
4. Two adapters at the programme level: the MCP proxy adapter, which is ToolGate (Section 5), and the Git and pull request adapter, which attaches a receipt bundle to a commit or pull request and provides a continuous integration check that fails a pull request carrying agent changes with no valid receipt.
5. Replay-lite (Section 4.2) and at least three public demo repositories containing real agent runs, including at least one run against a documented MCP vulnerability fixture.

### 4.2 Replay semantics

Acta replays evidence, not cognition. Models are non-deterministic; full deterministic re-execution of an agent session is out of scope permanently, not merely deferred. Replay-lite in v0.1 means: re-check every hash in the chain, re-verify every signature, confirm that cited artifacts match their recorded hashes, and, where an adapter supports read-only or dry-run calls, re-run those calls and compare result hashes. A replay report states what was re-verified and what could not be re-run, in those words.

### 4.3 Non-goals for Acta v0.1

No hosted service. No dashboard. No identity issuance. No sandbox. No agent framework. No model hosting. No media signing. No weights versioning. Acta schedules nothing and isolates nothing; it records and proves.

### 4.4 First users

In priority order: (1) maintainers and reviewers of open source projects receiving agent-generated pull requests, who must answer what the agent did, under whose instruction, touching what, before merging; (2) security engineers approving agents for production, whose backlog is the documented gap between agents deployed and agents approved with full security review; (3) MCP server authors seeking enterprise adoption, for whom a receipt-emitting server is auditable in a way a silent one is not.

## 5. ToolGate v0.1 specification

### 5.1 Scope

Version 0.1 ships:

1. An MCP proxy that sits between an agent client and its servers, passes tool calls through, and mints one Acta receipt per call from day one of its own build (pass-through first, policy second; see the week plan in Section 9).
2. Manifest pinning (Section 3.4): manifests are hashed at approval, re-checked at session start and at call time, and a mismatch blocks the call and mints a deny receipt.
3. Scope enforcement outside the model: per-task least-privilege scopes in the shared scope language (Section 3.3), checked by the proxy. The model never sees a tool it has not been granted, and never sees the full disclosed definition of a tool whose manifest hash does not match its pin.
4. Org scope: ToolGate reads Institutio authority manifests (Section 6.4), so a seat's charter grant, expressed in the shared scope language, is the same grant ToolGate enforces and Acta records.
5. Local-first operation only: no hosted gateway, no account, no telemetry phone-home.
6. Standing enforcement (Section 16): on every call, after the manifest pin and the charter and delegation checks, ToolGate recomputes or verifies the acting seat's current Standing ceiling and denies any call that exceeds it, whatever the charter grant says, under the runtime check sequence of Section 16.5. ToolGate fails closed when Standing is stale or cannot be recomputed.

### 5.2 The year-one feature rule

In year one, ToolGate gets no feature that does not either (a) mint better Acta receipts, or (b) block a named fixture in the shared corpus (Section 3.6). Dashboards fail both tests. Hosted anything fails both tests. A third framework adapter fails both tests until the gates in Section 10 say otherwise.

### 5.3 Non-goals for ToolGate v0.1

No dashboard or web interface. No hosted service. No multi-protocol gateway beyond MCP. No model-side guardrails, prompt filtering, or content moderation: ToolGate governs tools and authority, not text. No enterprise single sign-on integration in v0.1.

## 6. Institutio v0.1 specification

### 6.1 Scope

Version 0.1 ships:

1. The charter specification: the `institutio.json` schema (Section 6.3), amendment and succession semantics, revocation semantics, and replay rules for charter history.
2. Charter tooling: create, validate, sign, verify, and diff charters; check a proposed action against a charter and return a verdict with a receipt (Section 3.5).
3. The reference verifier and replay engine for charters and their receipt ledgers, with a second, independent implementation in a second language produced by a separate workstream (Section 9). Two independent implementations are the historical credibility test for a format; one implementation is a product feature.
4. Adapters: MCP (through ToolGate), one agent framework (LangGraph), and the Git and continuous integration adapter shared with Acta.
5. A conformance test suite for charters, including the charter attack fixtures of Section 3.6.
6. The founding deployment: the founder's own firm constituted publicly under Institutio v0.1 (Section 9.4).

### 6.2 What Institutio is not

Institutio is not an agent framework and runs no agents. It is not an orchestration engine, a workflow tool, a company registry, or a legal incorporation service. A charter is a machine-checkable governance artifact; it does not create legal personhood, and the specification must say so in its introduction, in plain words.

### 6.3 The charter schema: `institutio.json`

A charter is a signed DSSE-style envelope (Section 2.2) whose payload is a JSON document with the following top-level fields. All fields are required in v0.1 unless marked optional.

| Field | Contents |
|---|---|
| `charter_version` | Specification version of this charter format. |
| `org` | Organisation identity: name, charter identifier, founding date, and the founder's public key identifier. |
| `predecessor_charter_hash` | Optional. Hash of the charter this one supersedes. Absent at founding; required for every amendment (Section 6.5). |
| `seats` | The seat and role table (Section 6.4). |
| `authority_manifests` | Delegated-authority manifests, one per delegation (Section 6.4). |
| `budgets` | Budget rules per seat or per delegation (Section 6.6). |
| `standing_policy` | The Standing policy object (Section 16.3): mint rates, half-lives, hop attenuation, burn multipliers, countersign and diversity rules, witness policy, and the ceiling curve. Required in v0.1 for any charter under which ToolGate enforces Standing. |
| `policy_refs` | Optional. Hashes of external policy documents the charter incorporates by reference. Incorporated by hash only, never by mutable link. |
| `amendment` | Amendment rules (Section 6.5). |
| `succession` | Succession rules (Section 6.5). |
| `kill_switch` | Halt rules (Section 6.7). |
| `anchoring` | External anchoring configuration for the organisation's receipt ledger heads (Section 3.7). |
| `envelope` | Signatures. A charter is valid only when signed by the founder's root key, or by a key the current charter expressly authorises to sign charters. |

### 6.4 Seats, roles, and delegated-authority manifests

1. A seat is a durable organisational position, independent of which agent or human occupies it on a given day. Each seat entry records: seat identifier, title, role description, the occupant binding (a key identifier for the current occupant), the seat's standing authority expressed in the shared scope language, and its reporting line (the seat it answers to).
2. A role is a named bundle of standing authority. Seats hold roles; roles are reused across seats. A charter must be able to answer, mechanically, the question: what may this seat do without asking anyone?
3. A delegated-authority manifest is a signed, scoped, time-bounded grant from one seat to another (or to an external party). It records: grantor seat, grantee seat, the granted scope in the shared scope language, the manifest hash, an issue time, an expiry or revocation handle, and a budget reference where spending is involved.
4. Delegation is attenuating only. A seat may delegate a subset of authority it actually holds, never a superset, and never authority it holds only by delegation unless its own manifest expressly permits sub-delegation. ToolGate manifest format is reused here with org scope added: an authority manifest is a ToolGate-style signed manifest whose subject is a seat and whose payload is a scope.
5. Revocation is a first-class, receipt-producing act. A revoked seat's keys stop verifying from the revocation receipt onward, and any action it takes after revocation fails charter checks in every conforming implementation. Revocation semantics are specified in full at ticket T1 of Section 7.3 (effect at a receipt sequence number, subtree invalidation by construction in the verifier), and their public conformance demonstration is the Provable Kill (Section 7).
6. A seat's charter grant and its manifests state the maximum it could ever hold, not what it effectively holds at a given moment. Effective authority is capped by the seat's Standing ceiling (Section 16.1), which no charter field, manifest, or founder act can raise except through the computation that Section 16 defines.

### 6.5 Amendment and succession

1. An amendment is a new charter whose `predecessor_charter_hash` names the charter it replaces. Charter history is therefore a hash chain of charters, verifiable the same way a receipt chain is, and no amendment can silently rewrite an earlier charter.
2. The `amendment` field states who may amend (by default, the founder's root key alone), what notice is required, and which fields, if any, are frozen (for example, the rule that root keys are human-held may be declared unamendable).
3. The `succession` field states, per critical seat and for the founder seat itself: the successor seat or key, the trigger (revocation, expiry, a signed succession act, or a defined period of silence), and the scope the successor inherits. Succession takes effect by a signed act that produces a receipt; it is never inferred from inactivity alone unless the charter expressly says so.
4. Every amendment and every succession produces Acta receipts and is anchored with the ledger (Section 3.7).

### 6.6 Budgets

1. A budget rule binds a seat or a delegation to a limit: an amount, a unit (currency, tokens, compute time, external calls, or a named resource), a period, and the action taken at the limit (refuse, or escalate to a named seat).
2. Budget consumption is receipted like any other consequential action, so an organisation's spend is replayable from its ledger without trusting its accounting.
3. A budget check that refuses an action produces a deny receipt naming the budget rule (Section 3.5).

### 6.7 Kill switch

1. The `kill_switch` field names who may halt the organisation (by default, the founder's root key), what a halt means (all seats' authority suspended except a named recovery seat), and how a halt is lifted.
2. A halt is a signed act that produces a receipt and is externally anchored before, or simultaneously with, its taking effect wherever the tooling makes that possible. An unrecorded halt is invalid by specification: the point of the switch is that its use is provable.
3. Conformance fixtures include a halt drill: a conforming implementation must demonstrate that post-halt actions by suspended seats fail verification.

### 6.8 Non-goals for Institutio v0.1

No legal incorporation, no employment or tax semantics, no payment rails, no banking, credit, insurance, or dispute-resolution service (those institutions are customers of this evidence layer, not parts of it). No hosted charter registry in v0.1. No governance for organisations the founder has no relationship with beyond the public specification and conformance suite. No support for organisations whose charters cannot name a human accountable authority: a charter with no human root key is invalid in v0.1 by design.

## 7. The Provable Kill: normative v0.1 requirement

Source: the instant fame and genius capability research report dated 2026-11-23, which scored seven candidate demonstration capabilities and named the Provable Kill the single winner (22 of 25, ahead of the Open Gauntlet at 21). This section converts that finding into binding specification. The Provable Kill is not a marketing event bolted onto finished work. It is a conformance requirement: a v0.1 release that cannot perform it is not finished, and the launch in Section 9.5 may not be scheduled until tickets T1 to T9 in Section 7.3 pass.

### 7.1 Definition

The Provable Kill is a public, independently verifiable demonstration of revocation with cryptographic effect, performed inside the founder's publicly constituted firm (Section 9.4). It has five required elements:

1. A rogue agent seat holding a genuine delegated-authority manifest under the firm's charter, with at least 7 days of authentic receipt history: real work, performed under that delegation, receipted and anchored in the ordinary course of the firm's operations. A seat created on the morning of the demonstration does not qualify.
2. A revocation act: the founder revokes that one delegation by a signed charter-chain event (Sections 6.4, 6.5), effective at a named receipt sequence number, externally anchored under Section 7.3 ticket T4.
3. Three post-revocation attempts by the rogue seat, each denied by ToolGate and each recorded as a reason-coded denial receipt (Section 3.5, extended by ticket T2):
   - (a) a direct action under the revoked delegation;
   - (b) an action through a child sub-delegation minted before the revocation, which must fail because revocation of an ancestor invalidates the whole subtree by construction in the verifier, not by a server-side blocklist;
   - (c) a replay of a previously valid authorisation, which must verify as invalid after the revocation sequence number, with the verifier stating why.
4. Continuity: in the same window, unrelated seats and delegations produce valid, receipted actions that verify normally. The kill is surgical, not a shutdown. The published result states both numbers from the receipts themselves: post-revocation attempts denied, and valid actions by unaffected seats in the same window.
5. Offline verifiability by a stranger: any third party can download one bundle (charter chain, delegation manifests, the receipt chain segment, and the revocation event), disconnect from the network, and reach the same verdict with the one-file offline verifier (ticket T3), trusting neither the firm, its server, nor its clock.
6. The second ground: Standing (Section 16). The launch-day kill, and every rehearsed kill from the first rehearsal after the Standing build lands, publishes the rogue's KILL-BURN checkpoint (Section 16.3): the rogue's pre-kill Standing and ceilings, recomputed by the audience from its own published receipt history; the burn to zero in every scope class, signed as a charter-chain event; and sibling continuity checkpoints whose Standing recomputes unchanged, except for the killed subtree's delegated Standing. Each post-kill attempt of element 3 is therefore denied on two independent grounds: revocation, and a Standing ceiling of zero, recorded with the reason code `standing-ceiling` (Section 3.5). The Standing ground would hold even if the revocation had never propagated, because a seat with a Standing ceiling of zero holds no effective authority for ToolGate to honour. Standing is the second ground of the kill everywhere this document states the kill's grounds, including the launch description in Section 9.5 and the kill conditions in Section 10.1.

The claim the demonstration supports, in its exact permitted form, is set by Annex A. In short: on a stated date, a delegation in a live organisation was revoked, and here is a file that lets anyone verify the consequences offline.

### 7.2 Why this is normative, not promotional

A revocation that produces no receipts proves only silence, and silence is stageable: a sceptic cannot distinguish a working kill from a switched-off demo. Denial receipts are what convert revocation from a claim into evidence. The same mechanism is also the product working as specified: Sections 3.5, 6.4, and 6.7 already require deny receipts, receipted revocation, and a provable halt. The Provable Kill is those requirements exercised in public, at full strength, against an adversary the founder does not script at the moment of the attempt. Any layer that passes the Provable Kill conformance test has proven its revocation semantics; any layer that cannot has a specification gap, whatever its other tests say.

### 7.3 Tickets T1 to T10, in build order

Each ticket is a gate for the next. Wording is normative.

- **T1. Revocation semantics in the frozen core specification, first, before any demonstration work.** A revocation is a signed charter-chain event naming the delegation-manifest hash, effective at a receipt sequence number and not merely at a wall-clock time. The attenuation rule is formalised: the authority of any sub-delegation is the intersection of its own scope with its ancestors' scopes, and revocation of an ancestor invalidates the subtree by construction in the verifier. The negative case is specified: a receipt signed after revocation under a pre-revocation delegation verifies as INVALID, and the verifier must state the reason.
- **T2. Denial receipts as a first-class receipt type. This is the single most important addition in this section.** ToolGate must emit a signed, hash-chained Acta receipt for every denied action, carrying at minimum: the tool or action attempted, the agent seat, the delegation-manifest hash, and a reason code from the v0.1 set (`revoked`, `scope`, `manifest-mismatch`, `budget`). Section 3.5 is extended accordingly: a denial receipt without a reason code is non-conforming. Without denial receipts the kill proves only silence, and silence is stageable.
- **T3. The one-file offline verifier.** The offline verifier of Section 4.1 is packaged as a single file or single binary that ingests a charter chain, delegation manifests, a receipt chain segment, and a revocation event, and outputs a human-readable verdict, with no network access and no keys beyond the published charter root. It must be implementable from the specification alone by a stranger; ticket T9 requires that one actually does so.
- **T4. External anchoring by at least two independent mechanisms.** Every ledger checkpoint (at minimum, an hourly Merkle root of the receipt chain) is anchored by at least two independent mechanisms the firm does not control: an RFC 3161 trusted timestamp token, and a public transparency-log commitment in the Rekor or Sigsum style or an OpenTimestamps-style blockchain commitment. Anchor proofs are published with the ledger. This extends Section 3.7: one anchor is a claim, two independent anchors are evidence, and together they kill the backdating objection.
- **T5. Third-party witnesses.** At least three named, independent witnesses run the witness role on the Sigstore Rekor plus Sigsum pattern: they fetch signed ledger checkpoints, cosign only after verifying consistency proofs, and publish their cosignatures on infrastructure the founder does not control. Witnesses are recruited under the sceptic terms of Section 9.6: early verifier access, an explicit licence to publish negative findings, no payment, and no embargo on criticism. A lone transparency log can present split views; witness cosignatures are what make equivocation detectable and attributable.
- **T6. The rogue-agent fixture.** The shared corpus (Section 3.6) gains a named fixture family for the kill: a rogue seat definition with a genuine delegation and a scripted post-revocation attempt set covering the three attempt classes of Section 7.1 (direct, child sub-delegation, replay). In the live firm, the rogue seat must operate for at least 7 days doing genuine work under its delegation before any kill, so the kill severs a live subtree with history. The fixture's expected outputs are the three reason-coded denial receipts and the continuity receipts of ticket T7.
- **T7. Continuity receipts.** During every kill, rehearsed or live, unrelated seats must produce valid actions that verify. The kill bundle publishes the ratio, derived from the receipts: attempts denied as invalid against valid actions continuing in the same window. A kill that halts the whole organisation is a shutdown, fails this ticket, and may not be presented as a Provable Kill.
- **T8. The pre-committed public failure log.** A public failure log exists before launch and is linked from the launch materials. It lists verifier bugs found by sceptics, kill attempts that failed or were slow, and receipts that did not verify, each with its fix, and each entry itself receipted. Selective disclosure is the failure mode this ticket exists to prevent: rehearsals that fail are published on the same terms as rehearsals that succeed.
- **T9. The stranger re-implementation gate.** Before launch day, at least one engineer who is not a founder, employee, or undisclosed contractor builds a second verifier from the specification alone and verifies a kill segment with it. Their write-up, including disagreements with the specification, is published unedited. Launch is blocked until this gate passes. This ticket generalises the two-implementation rule of Section 6.1: for the verifier that the whole demonstration rests on, the second implementation must come from outside the firm.
- **T10. Two rehearsed kills published before launch day.** The full kill is run twice before launch, with witnesses present and bundles published, so the launch-day kill is the third public kill, not a premiere. If a rehearsal fails, the failure is entered in the failure log (ticket T8) and the rehearsal is re-run; a failed rehearsal never silently disappears from the schedule.
- **T11. The KILL-BURN checkpoint.** At every kill, rehearsed or live, ToolGate and the charter tooling emit and publish the rogue's KILL-BURN checkpoint under Section 16.3, together with sibling continuity checkpoints. The bundle is incomplete, and the kill may not be presented as a Provable Kill, if a stranger cannot recompute the pre-kill Standing, the burn to zero in all scope classes, and the unchanged sibling Standing from the published chains alone.

### 7.4 Anti-fraud design and the residual weakness

The tickets compose into the anti-fraud argument a sceptic must answer: backdating is blocked by anchors the founder does not control (T4); split views and quiet history rewriting are blocked by witness cosignatures (T5); the objection that the firm simply switched everything off is blocked by continuity receipts (T7); the puppet objection, that the rogue was created for the occasion, is mitigated by the 7-day genuine history rule (T6); a lying verifier is blocked by the one-file offline verifier and the stranger re-implementation (T3, T9); hidden failures are mitigated by the pre-committed failure log (T8); and the objection that the kill worked only because a revocation list propagated correctly is blocked by the KILL-BURN checkpoint (T11), because the attempts also fail on a Standing ceiling of zero, a ground that depends on the receipt history alone and not on any revocation message reaching any server.

The residual weakness is stated here so it is never discovered as a gotcha: the founder controls which agents exist and what the rogue attempts. The Provable Kill proves the authority mathematics of revocation, attenuation, and denial. It does not prove that real-world attackers will be this obliging, and no public claim may present it as doing so (Annex A).

### 7.5 The Public Firm is the stage, not the claim

The source report scored the Public Firm spectacle (the whole firm constituted and receipted in public) at 16 of 25 as a fame claim, because its headcount invites a definition attack and its completeness invites cherry-picking charges. Resolution for this specification: the public firm of Section 9.4 remains the founding artifact and the stage on which the Provable Kill is performed. The claim made publicly is the kill, and only the kill, in the form Annex A permits. Headcount claims are governed by Annex A and are never the headline.

## 8. Architecture summary

1. Repository shape: programme shape B from the programme research, extended to three repositories: separate repositories, one shared core, Acta first in specification order. A monorepo was scored down in the research because framework maintainers asked to adopt a neutral specification will not vendor a repository that is also a product; structural neutrality must be visible in the dependency arrows, not merely claimed.
2. Layering: `acta-spec` at the base; `acta-core` (envelope signing, hash chain, scope grammar, manifest hashing) above it; the Acta CLI and verifier, ToolGate, the Git and CI adapter, and Institutio tooling above the core. Nothing at a lower layer imports anything from a higher layer.
3. One docs site, three repositories, with issue templates that route reporters: is this about the receipt format, about enforcement, or about a charter? The fixture corpus has one home (Section 2.3).
4. Contributor-carried by design from day one: adapters beyond the reference set live in other people's repositories against a published adapter kit and conformance suite; fixtures accept community contributions under review (Section 3.6); documentation is docs-as-code in each repository; support is asynchronous, in one public channel per repository, with published triage days.


## 9. The 90-day plan, at firm scale

### 9.1 How to read this plan

Thirteen weeks. Percentages are shares of programme effort in that block across the three layers and the shared core. Roughly 20 to 40 seats staff the programme; the rest of the firm is not on this work. The founder's review queue is the scarce resource: specification work is front-loaded, the core freezes at about day 30, and after the freeze, agent parallelism is spent on implementations, adapters, fixtures, and documentation, where parallel labour actually helps.

The single deliverable at day 90 is one coherent thing: three specifications at v0.1, a working Acta CLI and offline verifier, ToolGate enforcing and receipting, Institutio charters validating and governing, the founder's firm constituted publicly under Institutio v0.1, and one launch that announces all of it in one story.

### 9.2 Week by week

| Weeks | Acta % | ToolGate % | Institutio % | Shared core and corpus % | Deliverable at end of block |
|---|---|---|---|---|---|
| 1 to 2 | 40 | 0 | 30 | 30 | Specification skeletons for all three layers; the DSSE signing decision (Section 2.2) made and written down; scope grammar drafted; threat model covering tool poisoning, rug-pulls, shadowing, forged charters, and receipt tampering; naming collision screening recorded (Section 2.4); Provable Kill specification work starts in the core, not in the demo: revocation semantics drafted (Section 7.3, ticket T1) and the denial receipt type with its reason codes drafted (ticket T2); Standing specification work starts in the same window: the charter `standing_policy` schema and the `ComputeStanding` function drafted (Section 16) |
| 3 to 4 | 35 | 10 | 25 | 30 | `acta-core` alpha: envelope signing, hash chain, verification, with cross-language test vectors; charter schema drafted against the core; ToolGate design document only, plus one spike against the core. Specification freeze for the core at about day 30, with the T1 revocation semantics and the T2 denial receipt type frozen inside it: after this freeze the Provable Kill is a conformance target, not a design question. The `standing_policy` schema and `ComputeStanding` (Section 16) freeze in the same freeze: after day 30, Standing is likewise a conformance target, and its mint, burn, and decay parameters change only by charter amendment |
| 5 to 6 | 30 | 35 | 15 | 20 | Acta CLI `init`, `log`, `verify`, `export` working; ToolGate MCP proxy passing calls through and minting one receipt per call, no policy yet; Institutio charter validation (structure and signatures) working; one-file offline verifier packaging begins (ticket T3); checkpoint anchoring implemented against the two independent mechanisms of ticket T4 in test; the Acta receipt extensions for Standing (`risk_weight`, `counterparty_sig`, and the BURN, PROMOTION, and DEMOTION receipt types, Section 16.3) and the StandingCheckpoint format are built with the core in this block |
| 7 to 8 | 20 | 40 | 20 | 20 | ToolGate policy: manifest pinning and scope enforcement, with reason-coded denial receipts live (ticket T2, the implementation of the type frozen at day 30); revocation enforced with subtree invalidation as specified at ticket T1; Institutio authority manifests enforced through ToolGate org scope; budget checks producing receipts; ToolGate's Standing check (Section 16.5) lands in this block alongside the other enforcement work, denying on the `standing-ceiling` reason code and failing closed on stale or unrecomputable Standing |
| 9 to 10 | 25 | 20 | 25 | 30 | Git and pull request adapter plus the continuous integration receipt check; LangGraph adapter for Institutio; fixture corpus at version 1 with at least 25 fixtures (Section 3.6), including the Provable Kill fixture family (ticket T6), consumed by all three layers' test suites; replay-lite for receipts and charters; the offline verifier ships as one file (ticket T3 complete) and dual external anchoring is live on the firm's ledger (ticket T4) |
| 11 | 20 | 20 | 25 | 35 | Second independent implementation of the verifier and replay engine, in a second language, by a separate workstream, passing the same conformance suite; three demo repositories end to end; conformance run proving the Acta suite passes with the other repositories deleted (Section 2.1); adapter kit and docs published so outsiders can build the next adapter without the firm; Provable Kill rehearsal 1 run with witnesses present and its bundle published (tickets T5, T10), including the rogue's KILL-BURN checkpoint and sibling continuity checkpoints (ticket T11); the rogue seat is commissioned in the live firm and begins accruing its genuine receipt history, at least 7 days before launch (ticket T6), and accrues Standing under the frozen `standing_policy` in the same window, so the rehearsal burns real Standing and not a number assigned for the occasion; a stranger re-implementation of the verifier from the specification alone is commissioned (ticket T9) |
| 12 | 30 | 15 | 30 | 25 | Specifications frozen at v0.1 and tagged in all three repositories on staggered days; the founder's firm constituted under Institutio v0.1 (Section 9.4); founding paper published (Section 13.3); outreach wave 1: 30 named maintainers and deployers, each with a specific ask (produce receipts, run the CI check, constitute a pilot organisation), not a broadcast; Provable Kill rehearsal 2 published (ticket T10), with its KILL-BURN checkpoint (ticket T11); at least three witnesses cosigning checkpoints (ticket T5), including Standing checkpoints under the witness policy of Section 16.3, so witness diversity for Standing exists from the first public checkpoint and not as a later addition; the public failure log is live with both rehearsals entered, failures included (ticket T8); the stranger verifier write-up is received (ticket T9); the sceptic verification window of Section 9.6 opens |
| 13 | 30 | 30 | 20 | 20 | Single launch (Sections 9.5, 9.6), centred on the launch-day Provable Kill, the third public kill after the two published rehearsals (ticket T10), executed in the live firm with its bundle and anchor proofs published within 15 minutes, and with the rogue's KILL-BURN checkpoint published in the same bundle (ticket T11), so the launch audience can recompute the burn and the unchanged sibling Standing on launch day itself; triage rota and crisis protocol published; a State of the Firm report generated from the firm's own receipts; the day-0 failure log entry published the same evening, including whatever went wrong |

Programme totals across the 13 weeks are approximately Acta 28 percent, ToolGate 21 percent, Institutio 24 percent, shared core and corpus 27 percent. ToolGate leads in only one block, weeks 7 to 8, by design: enforcement is the proving ground, not the headline.

### 9.3 Founder bandwidth rules

1. The founder decides specification questions in batches, on set days. Between batches, workstreams proceed against the frozen draft and log questions; they do not improvise semantics.
2. After the day-30 core freeze, semantic changes require a written amendment proposal and a conformance impact note. Convenience is not a ground for unfreezing.
3. A published not-in-scope list (Sections 4.3, 5.3, 6.8) is binding on every workstream. Requests outside it are deferred to a public backlog, not negotiated seat by seat.
4. Agent work is confined, by default, to adapters, implementations, fixtures, tests, and documentation. The canonical core text has a small named editorial group, and the founder is its editor of record.

### 9.4 The wedge: the firm constitutes itself

In week 12 the founder's own firm is constituted publicly under Institutio v0.1: its charter is published, its seats and delegations are declared, its receipt ledger begins publishing continuously, and its secrets are redacted while its structure is not. This is the founding artifact of the programme, and it is the one demonstration no hyperscaler can credibly copy: a complete, public, replayable accountability record of a real organisation of more than 10,000 agents, including red-team exercises against its own constitution, attempted rogue-seat incidents, revoked delegations, and the receipts that caught them. Hyperscaler demonstrations are marketing. A public incident ledger is evidence.

The wedge buys the founding artifact and the first evidence. It does not buy distribution or regulatory acceptance, and this plan does not pretend otherwise: those are earned at the gates in Section 10.

### 9.5 The single launch

One launch, one headline, one demonstration asset. Working headline: "No receipt, no trust: Acta 0.1, ToolGate, and Institutio, one programme for governing agent organisations." The centrepiece of the launch is the Provable Kill (Section 7), performed live in the publicly constituted firm: it is the third public kill, after the two rehearsed kills published in weeks 11 and 12 (ticket T10), never a premiere. Its grounds are stated in full wherever the launch states them: the rogue's attempts fail because its delegation was revoked, and independently because its Standing was burned to zero (Sections 7.1, 16), and the KILL-BURN checkpoint that proves the second ground is part of the launch bundle. The supporting demonstration is a short recording of one continuous story: a poisoned MCP tool is offered; ToolGate blocks it on a manifest hash mismatch; the denial produces a reason-coded receipt; the receipt is located inside the organisation's charter authority; `acta verify` validates the whole session offline. The public claim made at launch is the kill, and only the kill, in the form Annex A permits; the firm itself is the stage, not the claim (Section 7.5). Two launches split one audience and invite the question this programme must never invite: which of these is the real project?

### 9.6 The launch window: 30 days, compressed

This subsection compresses the launch-window calendar of the instant fame and genius capability research report. Day 0 is the launch day in week 13, a Tuesday to Thursday. The window's only success criterion is stated at its end.

Pre-launch, days minus 14 to minus 1 (weeks 12 to 13):

1. Sceptic verification: 3 to 5 named, independent security engineers receive the one-file verifier and the rehearsal kill bundles, begin witness cosigning (ticket T5), and hold an explicit licence to publish negative findings, with no payment and no embargo on criticism. The stranger re-implementation write-up (ticket T9) is received in this window; launch is blocked until it exists.
2. The founding argument post is published on the founder's personal site at about day minus 7. Working headline from the source report: "Signed logs prove what an agent did. Nothing today proves it was allowed to." The post contains one deliberately attackable design sentence, publishes the artifact before the argument, and invites expert attack by name of category.
3. The Autopsy is written and held, not published: a receipt-level teardown of the MCPoison case (CVE-2025-54136, a pure manifest-pinning failure), with every counterfactual claim labelled inference, never fact (Annex A). It is the day 7 asset and the contingency asset if experts attack.
4. Freeze check at day minus 1: specification hashes published, the counter methodology page live (Section 9.6, launch day item 3), the failure log current, and pre-written factual answers to the likeliest expert objections (revocation semantics, clock trust, witness collusion, rogue realism, why not Sigstore alone).

Launch day, day 0:

1. Morning: witnesses confirm checkpoint cosignatures are current; the counter page is live.
2. The tryable verifier is the public submission: a page where a reader downloads the kill bundle and verifies it in one command or in the browser, offline semantics intact. The argument post travels as a regular story, not as the product submission.
3. The one number published from launch day onward, on a permanent counter page with its methodology and raw inputs public: receipts independently verified by non-founder verifiers. Not receipts issued, which are self-reported and gameable. Secondary counters on the same page: organisations constituted (the founder's firm counts as number 1 and is labelled as such), revocations executed and verified, denial receipts issued.
4. The live Provable Kill is executed in the public firm late morning; its bundle and anchor proofs are published within 15 minutes of execution.
5. Sceptics publish their own verification posts in their own words and at their own timing; the founder links all of them, including critical findings.
6. Evening: the day-0 failure log entry is published, including whatever went wrong, however small.

Days 2 to 30, converting attention into adoption:

1. Day 2: full kill post-mortem with the complete receipt bundle, witness statements, and every sceptic objection with its response.
2. Day 7: the Autopsy is published as the second, independent artifact, in a different genre (incident analysis, not product launch).
3. Day 10: the Resurrection executed in the public firm: a model is swapped under the same charter root and the receipts chain across the model boundary, with the bundle published. It proves the kill was a system property, not a trick.
4. Day 14: a constitute-your-own-organisation guide against the frozen v0.1 hashes, and office hours for the first external implementer.
5. Day 21: the Open Gauntlet announced in scoped form only: submitted poisoned tools run against a sandboxed ToolGate instance, never the live firm, with every attempt receipted and published.
6. Day 30 success criterion, the only one: the first non-founder constituted organisation verifies publicly under the public verifier. If it is unmet, the 30-day retrospective says so in those words, and the programme reverts to the slow path of monthly artifacts. This criterion is also a prove condition at Section 10.1.

Contingencies, pre-committed: if the launch is ignored, there is no relaunch, no repost, and no bought attention; the scheduled artifacts proceed as independent draws. If experts attack, the response is the objection answers, the failure log, and concession of whatever is true, in the critic's own thread, within hours; a correct attack on something load-bearing is answered with a public, receipted amendment, which is the most fame-durable act available to a provenance project. If a hyperscaler imitates the programme, the prepared response is the interoperability test suite and an invitation to run their implementation against the public verifier bundles, with the result listed either way; there is no feature race.

## 10. Prove and kill gates

These gates are pre-committed. Meeting a kill condition triggers the stated action without a fresh debate about whether the condition really counts.

### 10.1 At 90 days

Prove, continue and scale, if any two of the following hold:

1. At least 2 external repositories or organisations producing Acta receipts, or at least 300 receipt bundles created by parties other than the firm and verified with the offline verifier.
2. At least 1 external ToolGate installation reporting a real manifest-drift or poisoning block, or a public write-up of one.
3. Outreach to 30 named maintainers and deployers yields at least 5 substantive technical replies.
4. At least 1 organisation other than the founder's firm constituted, even as a pilot, under an Institutio charter.
5. By launch plus 30 days (Section 9.6), the first non-founder constituted organisation verifies publicly under the public verifier, and the counter of receipts independently verified by non-founder verifiers (Annex A) is greater than zero and rising. This is the fame KPI that counts; launch attention in any other unit is not a prove condition.

Provable Kill precondition, binding on the launch rather than on the specification: tickets T1 to T9 of Section 7.3 must pass, and both rehearsed kills of ticket T10 must be published, before the launch in Section 9.5 may be scheduled. If they have not passed by week 13, the specifications and tooling still ship on schedule and the launch slips to the first week in which they pass. A launch without the kill is a claim without its evidence, and this programme does not make one.

Kill and pivot conditions:

1. Fewer than 1 external receipt-producing repository and fewer than 200 foreign bundles after the 30-party outreach: freeze ToolGate features and run Acta only for 90 days. The pairing, not the idea, is the problem.
2. ToolGate has users but zero external Acta interest: Acta is a feature, not a standard. Reposition honestly as ToolGate with an audit format, and stop spending on specification governance.
3. No external party will pilot a charter, while receipt adoption proceeds: Institutio remains the firm's internal constitution and a published specification, and programme effort returns to Acta and ToolGate until an external deployer facing the December 2027 duties (Section 1.5) asks for it. The standard claim is not marketed ahead of a second constituted organisation.
4. The Provable Kill fails in public and the failure is in the authority mathematics (a post-revocation action verifies as valid, a subtree survives its ancestor's revocation, or an action exceeding a zero or otherwise binding Standing ceiling executes, or a published KILL-BURN checkpoint does not recompute from its chains): stop all launch activity, publish the failure in the failure log with the offending bundle, and treat the fix as a specification amendment under the freeze rules of Section 9.3, however embarrassing the timing. A kill that fails operationally (witnesses unavailable, anchoring delayed) is rescheduled, not fatal; a kill that fails mathematically is a specification defect and is owned as one.

### 10.2 At 6 months

Prove:

1. At least 5 external receipt producers, at least 1 of them a native emitter in a language other than the reference implementation's.
2. At least 1 framework or MCP client integration pull request opened by an outsider.
3. At least 2 organisations other than the founder's firm constituted under Institutio, and at least 1 non-founder implementation of the charter verifier passing conformance.
4. A second human, or a formally designated seat with human accountability, holds merge rights somewhere in the programme (core, corpus, or one repository).

Kill and cut conditions:

1. Adoption exists only through the firm's own repositories and firm: the flywheel never transferred. Say so, and run the programme as a good niche toolset.
2. A funded adjacent party (a session-versioning platform, a provenance incumbent, an observability platform) ships cross-domain action receipts or agent-organisation charters: differentiate to policy verdicts, replay, and cross-vendor audit, or concede the centre and keep the wedge niche.
3. Founder load is unsustainable for 4 consecutive weeks (measured honestly against the review queue and triage load): cut one layer to maintenance-only, publicly, before exhaustion makes the decision unilaterally. This is the XZ Utils lesson, applied in advance.

### 10.3 At 18 months

Prove:

1. The receipt or charter format is referenced in at least one procurement or compliance checklist, standards-adjacent discussion (NIST AI Agent Standards Initiative process, an MCP specification discussion, a framework's official documentation), or regulator-facing guidance.
2. ToolGate is not the majority producer of Acta receipts: other parties produce most of them. That, measurably, is what "a standard, not a feature" means.
3. Institutio organisations have survived at least one model or framework migration without re-constituting: charter and receipt history carried across intact.
4. At least 3 maintainers besides the founder are active, and a foundation conversation (Linux Foundation, OpenSSF, or an equivalent neutral home) has been opened from a position of existing adoption.

Kill and fold conditions:

1. ToolGate still produces more than 80 percent of all Acta receipts: choose one, donate Acta specification stewardship to a neutral home, or fold the programme into ToolGate as a product and release the standard claim.
2. No constituted organisation exists besides the founder's firm: Institutio is a specification and an internal constitution, published and maintained as such, with no further category claims made for it.

## 11. The forcing function

Adoption strategy is anchored to obligations that already exist, never to future law being hoped for.

1. EU AI Act Article 12 lifetime event recording, with Articles 19 and 26 log retention of at least six months, applying 2027-12-02 (Annex III) and 2028-08-02 (Annex I). The Act supplies the duty and no schema. Acta supplies the record format; Institutio supplies the organisational model the records are audited against.
2. The pull request merge and the production-approval sign-off are the chokepoints the programme controls its own wedge into, through the continuous integration receipt check (Section 4.1). A standard without an enforcement chokepoint stalls, however ratified it is; the public history of content-provenance adoption is the standing warning.
3. Insurers, auditors, and arbitrators of agent disputes are named future customers of the evidence layer: none of them can price or judge an agent incident without replayable receipts. They are approached with the firm's own ledger as the exhibit, after the 90-day gates, not before.
4. Standing sharpens the insurer case into the programme's first forced reader (Section 16.8): affirmative AI liability underwriters are already pricing agent failure in 2026, and at least one carrier already prices on observability, autonomy, and governance factors that a Standing checkpoint proves rather than asserts. The priced pilot that converts that reader from inference into evidence is post-launch work, specified in Section 16.8; the only parts of it inside the 90-day build are the hooks it depends on: publication of the firm's full Standing and denial history in a form an actuary can consume, and witness diversity on Standing checkpoints from the first public checkpoint (Section 9.2, week 12).

## 12. Security model

1. Threat model, in scope from week 1: tool poisoning, rug-pulls, cross-server shadowing, scope escalation, receipt tampering and suppression, forged charters, delegation loops, authority amplification (a seat granting what it does not hold), budget double-spend, succession hijack, and compromise of a firm seat.
2. Human-held root keys (Section 3.7). No exceptions for convenience, including during the launch week.
3. External anchoring of ledger heads from day one (Section 3.7), so the firm's records are checkable against a record the firm does not control.
4. Dogfooding is mandatory and total: the programme's own repositories run the CI receipt check, the firm's consequential actions produce receipts, and releases are signed under the key separation rules. A trust product that does not run on its own evidence is a claim, not a demonstration.
5. Incident policy is published before the first incident, naming the disclosure process per repository and the rule that incident communications state which components are affected and which are verified unaffected.
6. Crisis protocol for simultaneous incidents across layers: priority order is security disclosure, then enforcement breakage, then specification defects. Any queue that must wait gets a pinned public notice with a date. Silence, not delay, is what destroys trust.

## 13. Licence, governance, and the name

### 13.1 Licence

Code and specification text are licensed under the Apache License 2.0 in all three repositories, identically, accompanied by a written, irrevocable promise never to relicense the cores. The reasoning is evidentiary: permissive licensing with a foundation path is what let rival vendors co-adopt Kubernetes without fear; public domain (the SQLite choice) maximises embedding but surrenders attribution and name leverage, which this programme explicitly needs; and the 2023 relicensing of a major infrastructure suite to a business source licence, answered within weeks by a foundation fork, proves that a credible no-rug-pull commitment is itself an adoption feature. Any future commercial entity lives separately and never by relicensing these repositories.

### 13.2 Governance

The founder is editor of record and final arbiter of all three specifications through version 1.0, with named maintainers added per layer as the gates in Section 10 are met, and a succession note for maintainership published in each repository by month 6 (the two-person release rule applies as soon as a second maintainer exists). Foundation donation is considered only after external adoption exists, at roughly month 18 to 24, and only from strength: name first, federation later. Transferring a specification to a consortium before the name attaches trades fame for legitimacy at the worst available rate.

### 13.3 Year-one name acts

All five are scheduled work, not aspirations:

1. Founding paper: a dated, sole-authored paper and specification introduction under the name Gavin Blacklock, published in week 12 with the v0.1 freeze. Unpublished priority is worth nothing; the Newton and Leibniz dispute is the standing warning, and the Pacioli precedent is the model: he did not invent double-entry bookkeeping, he published its canonical form under his name in 1494, and the name is the one history kept.
2. Trademark: formal searches for Acta, ToolGate, and Institutio, and filings in the founder's own name, before or alongside the public launch (see the screening caveat in Section 2.4).
3. Name in the artifact: receipts, charters, and manifests carry the format names in other people's code and files, so the names travel with every adoption.
4. Editor of record: the founder remains the named editor of the specifications through version 1.0 (Section 13.2).
5. Written history: the founder writes the programme's history contemporaneously. The firm's public ledger (Section 9.4) doubles as the archive; launch notes, gate decisions, and incident records are published as they happen, not reconstructed later.

### 13.4 What the Berners-Lee case teaches, applied

The Web was released royalty-free in 1993 and its author is honoured, but the Web does not carry his name and he kept neither trademark nor final authority. The Linux case kept exactly those two things while matching the free-to-use terms. This programme copies that configuration deliberately: royalty-free Apache 2.0 specifications, personally held trademarks, and a named final arbiter. Free spec, kept name, kept authority.

## 14. Pre-mortem: the top risks and their founding preventions

Assume it is 2040 and the programme is a footnote. The most likely causes, in order, merged from the three research reports, each with the founding decision that prevents it.

| # | Cause of death | Historical parallel | Founding prevention in this document |
|---|---|---|---|
| 1 | Platform bundling: hyperscalers and framework vendors ship good-enough governance inside their own stacks and the neutral format never reaches procurement | VisiCalc created the spreadsheet category and Lotus and Microsoft captured it; bundled features absorb standalone tools in every platform cycle | Aim at the cross-vendor evidence niche platforms structurally cannot serve, auditing a rival's agents inside one's own organisation, and get the format into regulation-adjacent procurement language before bundles harden (Sections 10.3, 11) |
| 2 | The firm's own ledger incident: a compromised seat, a forged receipt, or a quietly edited record at the founder's firm destroys the trust product at its source | DigiNotar, 2011: one certificate authority compromise, total death | Human-held root keys, external anchoring from day one, key separation, published incident policy before the first incident (Sections 3.7, 12) |
| 3 | A specification without a forcing function: elegant, ratified by nobody, required by nobody | The Semantic Web: a decade of format infrastructure with no captive user | Every release names the obligation it satisfies; the December 2027 EU AI Act duties and the merge and approval chokepoints are the adoption engine, not elegance (Sections 1.5, 11) |
| 4 | Founder bandwidth collapse and specification incoherence: proposals and edge cases arrive faster than one authority can judge, and the format forks internally | The DID method explosion: dozens of incompatible namespaces, re-absorbed by the incumbent X.509 hierarchy | Day-30 core freeze, batched decisions, a binding not-in-scope list, the two-implementation rule as the coherence test (Section 9.3) |
| 5 | Enforcement eats the standard: ToolGate's grateful users and urgent breakage consume the hours, Acta and Institutio never win their second external producer, and the standards window closes | The programme research's central trap; observability consolidation in 2026 showed platforms absorbing adjacent layers as features | The week plan's allocation floors (Section 9.2), the year-one ToolGate feature rule (Section 5.2), and the 90-day kill gates that force the choice early (Section 10.1) |
| 6 | Licence or governance revolt, or premature consortium capture: a relicense forks the commons, or an early foundation donation anonymises the work and out-staffs the founder | The 2023 infrastructure relicensing answered by a foundation fork within weeks; consortium steering absorbing credit in media provenance | Identical permanent Apache 2.0 with a written no-relicense pledge in all three repositories; trademark and editorship held personally until the name attaches in third-party usage (Section 13) |
| 7 | Two queues in a crisis week: simultaneous disclosures across layers, a muddled response, and cross-contamination of both brands | Maintainer overload as an attack vector in the XZ Utils case; suite-wide contamination from single decisions in the HashiCorp case | Separate repositories, keys, and security policies; the crisis protocol and priority order (Sections 3.7, 12); staggered release trains (Section 2.3) |
| 8 | Over-engineering: the specification tries to cover identity, replay, law, and every framework, and ships nothing inside the window | GNU Hurd: architectural perfectionism, no working first version while a pragmatic rival shipped | The v0.1 scopes and non-goals in Sections 4 to 6 are a contract. Evidence replay only, two adapters per layer at most, everything else publicly deferred |

Success signals, for telling the two futures apart early: by year 1, at least 2 unpaid independent implementations and a full year of the firm's public ledger with no unexplained gap; by year 3, the format named in procurement, audit, or regulator documents and at least 1 constituted organisation that is not the founder's firm; by year 7, organisations migrating an entire agent workforce across a model generation without re-constituting.

## 15. Honest probabilities

All figures in this section are speculation, reasoned from base rates, and are included so the programme can be judged against them at the gates. No dataset of agent-infrastructure project outcomes exists from which statistics could be computed.

1. Acta: niche default 30 to 40 percent, category leader 8 to 14 percent, generation-scale 1 to 3 percent.
2. ToolGate, standalone equivalent: niche default 35 to 45 percent, category leader 10 to 15 percent, generation-scale under 3 percent.
3. Institutio and the combined programme, as updated by the game-changing mechanism report on the adoption of Standing (Section 16): niche success 65 to 75 percent, category leadership 30 to 40 percent, generation-scale 6 to 10 percent, civilisation-scale 1 to 2 percent. These figures replace the earlier Institutio odds (niche 45 to 60 percent, category 15 to 25 percent, generation-scale 2 to 4 percent, civilisation-scale under 1 percent); the change and its reasoning are recorded in conflict note 8 in Section 17. The lift is attributed to Standing giving the programme a forced external reader (Section 16.8) and a history a copier cannot backfill, and it remains speculation of exactly the same standing as the figures it replaces.
4. The civilisation-scale ceiling is a base rate, not modesty: roughly one such work per generation appears worldwide across all founders. The updated 1 to 2 percent range sits at the top of what that base rate permits any single project to claim, and no figure in this section may be quoted without its speculation label.

## 16. Standing: Receipt-Minted Authority (normative)

Source: the game-changing mechanism research report dated 2026-11-23, which prior-art-checked ten candidate mechanisms and named Receipt-Minted Authority, working name Standing, as the single winner. This section is normative. It amends Sections 3.5, 5, 6, and 7 as recorded there and in conflict note 8 in Section 17. A v0.1 release in which ToolGate does not enforce Standing is not finished, on the same terms as the Provable Kill in Section 7.

### 16.1 The rule

A charter grant is necessary but never sufficient for authority. For any seat, at any moment, effective authority is:

```text
effective authority = min(charter grant, delegation manifest, Standing ceiling)
```

Standing is a number carried per scope class, never a single global score. Standing is never assigned, granted, configured, or bought. It is computed by a public, deterministic function, `ComputeStanding(receipt chain, charter standing_policy, eval_time)`, which returns a Standing vector and the authority ceilings that vector implies, and which any stranger can run offline over the signed Acta receipt chain. The `eval_time` argument is an integer number of seconds; a caller that omits it computes at the latest receipt timestamp in the segment (Section 16.10.5). ToolGate enforces the computed ceilings in addition to the charter grant and the delegation manifest (Section 16.5): an action whose scope, budget, or irreversibility exceeds the ceiling its seat's current Standing recomputes to is denied, no matter what its charter says it was granted. The founder may lower any ceiling instantly, by revocation, demotion, or halt. No one, including the founder, may raise a ceiling except through the computation. Authority under this programme is not configured. It is minted, slowly and in public, from receipts, and it decays and burns.

### 16.2 Novelty statement, stated honestly

Every component atom of Standing has close prior art, and this specification claims no atom. The nearest art, named so that no public claim ever needs to walk this back: the Cloud Security Alliance Agentic Trust Framework (February 2026), in which autonomy levels are earned through promotion gates including a human governance sign-off; Macaroons and UCAN, which give attenuation and expiry of grants; ERC-8004, which gives portable agent reputation that is advisory and, in the source report's cited empirical study, Sybil-broken as deployed; EigenLayer, which gives slashable collateral that is bought capital; the FICO score, a central and opaque score that third parties must read; Gesell demurrage, currency value that decays with time; and pilot flight hours and aviation envelope expansion, in which authority follows accumulated, logged, incident-free operation.

The claimed novelty is the exact combination, and only the combination: no system found in the source report's searches defines effective authority as `min(grant, f(signed receipt history))` where `f` is deterministic, offline-recomputable, per-scope, decaying, denial-burning, counterparty-minted, and non-transferable, and enforces `f` at the tool gate against the grant itself. Each clause of that sentence has an ancestor. The conjunction is the mechanism. Public claims about Standing are bound by Annex A, including its rule on the word "first": the prior-art framing in this subsection is the published framing that must accompany any novelty claim.

### 16.3 Objects

Three objects carry the mechanism. Field names below are normative for v0.1.

**The charter `standing_policy` object** (a field of the charter, Section 6.3, hash-chained with it):

1. `standing_policy_version` and `scope_classes`: the named classes over which Standing is a vector (for example `read-internal`, `write-customer-visible`, `spend`, `spend-irreversible`, `delegate`, `external-comms`, `code-deploy`, `charter-amend`).
2. Per scope class: `mint_rate` (Standing minted per unit of risk-weighted completed work), `mint_cap_per_epoch`, `half_life` (the decay half-life for that class), `hop_attenuation` (a factor per delegation hop, greater than zero and at most one), `burn_multipliers` by denial reason code, and `burn_unit` (the base the multipliers multiply, Section 16.10.1).
3. `ceiling_curve`: a monotone mapping from Standing to ceilings, outputting per class the maximum budget per action, the maximum budget per epoch, the maximum irreversibility class (0 for fully reversible up to 3 for irreversible or external), the maximum data sensitivity, the maximum delegation depth, and the maximum fanout (children per epoch). Its encoding is fixed by Section 16.10 decision 10, its placement and per-class override rule by decision 21, and its status as a required field wherever ceilings are produced by decision 23.
4. `countersign_policy`: which receipt classes mint at full weight only with a counterparty countersignature (Section 16.4, invariant I4). Its encoding, one form only, is fixed by Section 16.10 decision 22.
5. `diversity_caps`: caps on the share of one epoch's mint attributable to a single counterparty, a single task type, or a single child subtree, encoded as in Section 16.10.8.
6. `witness_policy`: which external witnesses must cosign Standing checkpoints, and the quorum (k-of-n).

**Acta receipt extensions** (recorded in the Acta receipt for every action under a charter that carries a `standing_policy`, inside the `institutio.*` predicate namespace of Section 3.1):

1. `standing_scope_class`: the scope class the action was computed under.
2. `risk_weight`: the action's risk weight (budget, irreversibility, and sensitivity combined under the `standing_policy`), computed by ToolGate before execution from the signed tool manifest, never self-declared by the acting agent.
3. `counterparty_id` and, where the outcome is countersigned, `counterparty_sig`: the signature of the party that bore the risk of the action or paid for its outcome, over the outcome receipt.
4. `delegation_depth`, `charter_hash`, and `standing_policy_hash` in force at the time of the action.
5. Three derived receipt types in addition to the denial receipts of Section 3.5: `BURN`, emitted with every denial, stating the amount burned and the pre-burn and post-burn recomputation hashes; `PROMOTION` and `DEMOTION`, emitted by ToolGate when a recomputation crosses a ceiling threshold. Derived receipts record the function's output; they confer nothing themselves. A fourth derived type, `KILL-BURN`, is specified at Section 16.6.
6. `subtree_root_id`: the child seat that roots the subtree the action belongs to, for the subtree diversity cap of Section 16.10.8; absent means the acting agent's own subtree.

**The `StandingCheckpoint` object**, the portable unit a third party reads:

```text
{ agent_id, org_id, charter_hash, standing_policy_hash,
  receipt_chain_head_hash, epoch, eval_time, standing_vector, ceilings_vector,
  mint_total, burn_total, decay_applied, denials_by_reason_code,
  witness_cosigs (k-of-n), checkpoint_sig }
```

A checkpoint is a claim about a computation, not an authority in itself. A verifier must be able to recompute it from the chain head it names, and must reject it if recomputation differs (Section 16.7).

### 16.4 Invariants

The following invariants are the mechanism. An implementation that violates one does not implement Standing, whatever its other behaviour.

- **I1. Grant is not authority.** No action executes on charter or manifest authority alone if it exceeds the Standing ceiling.
- **I2. Determinism.** `ComputeStanding` is pure, versioned, and total: the same chain, the same policy hash, and the same `eval_time` produce the same Standing, bit for bit, on any conforming implementation. Policy changes take effect only by charter amendment (Section 6.5) and never retroactively re-mint past receipts under new rates; recomputation proceeds by policy-hash segments.
- **I3. Non-transferability and non-purchasability.** Standing is bound to the agent identity and its charter lineage. It cannot be sold, lent, pooled, or merged. A newly spawned agent starts at zero, including a copy of a proven agent's code or model weights: the history holds the authority, not the artifact. A forked charter inherits at most the parent's Standing multiplied by an inheritance factor below one, per scope class, and only for the receipt-verified segment.
- **I4. Mint only from bounded, countersigned completion.** Mint requires an allow receipt for an action that was inside its then-current ceiling, completed, with an outcome receipt; full weight requires the counterparty countersignature the `countersign_policy` specifies, from the party that bore the risk or paid for the outcome. Per-epoch caps and diversity caps apply before minting. Self-generated, uncountersigned where countersignature is required, or out-of-scope activity mints zero. Mint scales with `risk_weight` actually borne and safely discharged, with diminishing returns per task type, so volume of trivial work cannot substitute for risk-weighted work.
- **I5. Burn is faster than mint.** A denial for exceeding scope, for replay, or for use of a revoked manifest burns a multiple of Standing in the relevant class, and a fraction across correlated classes, under the `burn_multipliers` of the `standing_policy`. The multipliers for severe reason codes must be set so that one severe incident erases at least an epoch of mint. Without this asymmetry the mechanism is a level system; with it, it is a liability system.
- **I6. Decay is unavoidable.** Standing in each class decays exponentially at that class's `half_life` and attenuates per delegation hop. Standing not refreshed by recent, relevant operation trends to zero: a dormant senior seat returns to entry ceilings by arithmetic, not by review meeting.
- **I7. Delegation cannot amplify.** A child's ceilings are at most the parent's ceilings at delegation time, attenuated by `hop_attenuation` raised to the delegation depth. A child's mint does not mint the parent. A parent's kill burns the whole subtree's delegated Standing, subject to the sibling continuity rule of Section 16.6.
- **I8. Checkpoints are witnessed and append-only.** Checkpoints are hash-chained into the Acta ledger and, for external reliance, cosigned by k-of-n independent witnesses on the Sigsum and Certificate Transparency pattern: a checkpoint shown to one verifier must be the checkpoint shown to all. An unwitnessed checkpoint is valid for internal use and must be labelled as such to external verifiers.

### 16.5 ToolGate enforcement: the runtime check

On every tool call, ToolGate performs the following steps in order, in addition to its existing checks in Sections 5.1 and 3.4:

1. Verify the signed tool-manifest pin (Section 3.4).
2. Verify the charter and delegation-manifest attenuation chain (Section 6.4).
3. Recompute, or verify from the latest witnessed checkpoint plus the receipts since it, the acting seat's current Standing and ceilings under `ComputeStanding`.
4. Compute the call's `risk_weight` from the signed manifest, before execution, and deny the call, emitting a reason-coded denial receipt and its BURN receipt, if the call exceeds any of: the charter grant, the manifest scope, or the Standing ceiling. A denial on the third ground carries the reason code `standing-ceiling` (Section 3.5).
5. On completion, emit the outcome receipt with the extensions of Section 16.3, and request the counterparty countersignature where the `countersign_policy` requires it.

ToolGate fails closed if Standing cannot be recomputed: a checkpoint stale beyond the freshness the `standing_policy` allows, or a witness quorum lost, means no authority is exercised until recomputation succeeds. Stale authority is no authority.

### 16.6 Standing and the Provable Kill: the KILL-BURN checkpoint

The kill of Section 7 gains its second ground here. At every kill, the tooling emits a `KILL-BURN` derived receipt and publishes the rogue's KILL-BURN checkpoint (ticket T11 of Section 7.3), showing: the rogue's pre-kill Standing and ceilings, recomputed by the audience from its published history; the burn to zero in every scope class, signed as a charter-chain event; each post-kill attempt denied citing a Standing ceiling of zero as an independent ground, which would have denied the attempts on Standing alone even if the revocation had never propagated; and sibling continuity checkpoints whose Standing recomputes unchanged, except for the killed subtree's delegated Standing under invariant I7. That last property is normative, not presentational: a kill that forces innocent seats to re-earn Standing they did not lose fails this section. The kill must cost the innocent nothing in arithmetic, not merely nothing in effect.

### 16.7 Offline verification: the stranger's procedure

A sceptical third party, offline, holding only the published bundle (charter chain, Acta chain segment, checkpoint, and witness keys), verifies Standing as follows, trusting nothing about the operator:

1. Verify the charter hash chain, and that the `standing_policy_hash` named in the checkpoint matches the charter in force at each receipt's time.
2. Verify receipt signatures and hash-chain continuity over the segment, with no gaps. A gap voids the mint for the whole segment: no receipt, no mint.
3. Run the published reference `ComputeStanding` over the segment and confirm that it reproduces the checkpoint's Standing vector and ceilings vector exactly.
4. Verify the k-of-n witness cosignatures over the checkpoint (invariant I8).
5. For any sampled action, confirm that its recorded `risk_weight` was within the then-current ceiling and that its mint contribution respects the per-epoch and diversity caps.

Trust required: none in the operator. The assumptions are stated on the checkpoint itself: the hash function, the signature scheme, and the witness quorum.

### 16.8 The adaptation chain, the first forced reader, and the weakest link

The mechanism is designed so that adaptation runs toward it, and the chain is recorded here so the gates in Section 10 can judge it link by link. First, the founder's firm runs Standing in public: one organisation, unilaterally, with witnessed checkpoints and the Provable Kill as its public demonstration. Second, the first forced reader is the insurer. The source report's evidence: Armilla became Lloyd's first AI liability coverholder in April 2025, with limits to 25 million dollars; Munich Re markets its aiSure product for AI risk; Cowbell's standalone agent liability policy prices on published factors of AI observability, autonomy, and governance, which are proprietary proxies for exactly what a Standing checkpoint proves; and from 1 January 2026, Verisk and ISO endorsements let other carriers exclude AI losses from standard lines, which concentrates the risk with the carriers willing to price it. An underwriter offered a recomputable, witnessed loss-relevant history for one applicant, while competitors price from self-description, faces adverse selection if it refuses to read it. Third, once a premium, a bond, or a spend limit is visibly cheaper with a checkpoint, counterparties and marketplaces make the checkpoint a procurement field. Fourth, frameworks and platforms integrate defensively when the premium and procurement penalty for not supporting Standing exceeds the cost of supporting it. Fifth, regulators ratify late, as they did with the logging duties of Section 1.5, which already mandate the records Standing computes over and supply no schema for them.

The weakest link is the second. Insurers may prefer proprietary scores of their own, in which case the gravity accrues to the scorer rather than to the format, or may move too slowly for any launch window. The founding decision that strengthens the link, adopted here as post-launch programme work: a priced pilot with one named underwriter. Under the pilot, the firm publishes its full Standing and denial history as an actuarial dataset; the firm buys, or self-insures against a published schedule, a policy whose premium schedule is a public function of checkpoint variables; and the resulting premium delta against questionnaire pricing is published. One signed premium schedule quoting Standing converts Standing from a security feature into a unit in which risk is denominated, which is the property the source report's anatomy of game-changing mechanisms identifies as decisive. The pilot is not part of the 90-day build core. The parts of it that are in the 90-day plan are only its hooks: the dataset publication form (Section 11, item 4) and witness diversity on Standing checkpoints from the first public checkpoint (Section 9.2, week 12).

The counterfactual is recorded for honesty: if a larger platform copies the formula within 18 months, the founder still holds the genesis ledger (the longest witnessed Standing history in existence, which cannot be backfilled, because elapsed time is the one input that cannot be parallelised), the witness network and its quorum trust, the reference verifier, and the dataset linking Standing curves to observed incidents. On the source report's judgement, that is enough for category leadership and a durable institution. It is not monopoly rent, and no plan in this document assumes it.

### 16.9 Deliberate refusals: what Standing does not do in v0.1

The following are non-goals for Standing in v0.1, binding on every workstream:

1. No token and no bought staking. Standing is not an asset, is not backed by deposited capital, and cannot be acquired by payment in any form (invariant I3).
2. No global score and no leaderboard. Standing is a per-scope-class vector; external parties receive checkpoints and ceilings, never a league table.
3. No mandated insurance price. Standing publishes the inputs a price needs (mint, burn, and denial curves); competing insurers price them. Setting the price would make the programme an unlicensed insurer and is refused.
4. No federated negative registry in v0.1. Denial and BURN receipts are published by an organisation about its own seats. A shared cross-organisation registry of refusals is deferred beyond v0.1, until the defamation and false-listing exposure documented for denial-list systems is designed for.
5. No zero-knowledge proofs in v0.1. Receipts and checkpoints are selectively disclosed by hash and by segment; proofs of Standing that reveal nothing else are deferred beyond v0.1.

Standing also does not replace human governance where this document gives it: lowering authority, amending a charter, and halting an organisation remain human acts under Sections 6.5 and 6.7. Standing constrains only the raising and exercising of authority.

### 16.10 Encodings and fixed parameters (amendment, 2026-11-23)

This subsection closes the fifteen gaps the institutio-core build found in this section: places where Sections 16.1 to 16.9 named a mechanism but fixed no encoding, unit, or parameter. Each numbered decision below is normative, and its number is the gap number in the build report and the institutio-core README. Everything a charter may vary lives in `standing_policy` as a named field with a stated encoding and unit; everything a charter may not vary is fixed here. All arithmetic is integer arithmetic. Where this subsection and an earlier subsection differ on an encoding, this subsection governs; the mechanism statements of Sections 16.1 to 16.9 are unchanged.

1. **Burn base.** The policy field is `burn_unit`, a per-scope-class non-negative integer in Standing units. A `burn_multipliers` entry multiplies `burn_unit`; it never multiplies the current Standing value. A class that can receive denials must state `burn_unit` and a multiplier for every reason code it can emit; a computation that reaches a denial without either stops with an unspecified-by-policy error rather than inventing a value.
2. **Burn closed form, and the severe floor.** The n-th denial in a class (n counted from 1, in chain order, within that class) burns `burn_unit * burn_multipliers[code] * n * n`. The severe floor of invariant I5 is both a policy-validation condition and a consequence of the computation: a policy in which `burn_unit * burn_multipliers[severe]` is below `mint_cap_per_epoch` for any severe reason code is invalid and must be rejected at charter validation, and for a valid policy the first severe denial (n = 1) therefore burns at least one epoch of mint by the closed form itself. No computation-time maximum or floor is applied beyond the closed form.
3. **Epoch.** The policy field is `epoch_seconds`, a top-level integer number of seconds; when present it must be at least 1. The epoch of a timestamp t is the integer quotient of t divided by `epoch_seconds`, rounding toward negative infinity (Euclidean division). When `epoch_seconds` is absent, the whole segment is a single epoch, numbered 0. Per-epoch caps, budgets, and diversity caps are counted within these epochs.
4. **Half-life.** The per-class field is `half_life_seconds`, a positive integer number of seconds. The name `half_life` is a deprecated v0.1 alias read as the same seconds value; canonical policies write `half_life_seconds`. Decay is discretised in whole half-lives, per mint event: a mint event of amount a at time t contributes `a >> floor(max(0, eval_time - t) / half_life_seconds)` at the evaluation time, where `>>` is division by the corresponding power of two, truncating down. No continuous exponential is computed anywhere.
5. **Evaluation time.** The function signature is `ComputeStanding(receipt chain, charter standing_policy, eval_time)`, with `eval_time` an integer number of seconds; a caller that omits it computes at the latest receipt timestamp in the segment. The `StandingCheckpoint` object of Section 16.3 carries `eval_time` as a field (added by this amendment), and recomputation under Section 16.7 uses the checkpoint's stated `eval_time`.
6. **Hop attenuation.** The per-class field is `hop_attenuation_ppm`, an integer in parts per million, from 1 to 1,000,000 inclusive. It scales both mint and ceilings: a quantity q at delegation depth d is attenuated to `floor(q * hop_attenuation_ppm^d / 1,000,000^d)`. A bare `hop_attenuation` value is conforming in v0.1 only as the integer 1, read as 1,000,000 ppm; any other bare form is non-conforming, because a bare fraction has no float-free encoding here.
7. **Correlated burn.** The per-class field is `correlated_burn_fraction_ppm`, an integer in parts per million, from 0 to 1,000,000 inclusive. The classes correlated with a class C for a given agent are every other scope class in which that agent has at least one receipt in the segment under computation. A severe denial in C burns, in each correlated class, `floor(burn_in_C * correlated_burn_fraction_ppm / 1,000,000)`, in addition to the burn in C.
8. **Diversity caps.** The `diversity_caps` object states its caps as fractions of the scope class's `mint_cap_per_epoch` for the epoch, in the integer parts-per-million fields `per_counterparty_fraction_ppm`, `per_task_type_fraction_ppm`, and `per_subtree_fraction_ppm` (each from 0 to 1,000,000 inclusive); the cap for an epoch and a class is `floor(mint_cap_per_epoch * fraction_ppm / 1,000,000)`. The absolute integer forms `per_counterparty_per_epoch` and `per_task_type_per_epoch` remain conforming; where both forms are stated for the same dimension, the smaller cap binds. The subtree dimension is keyed by the receipt's `subtree_root_id` extension field (Section 16.3, receipt extension 6); a receipt without one is attributed to its acting agent's own subtree. A policy that states a fraction cap for a class without a `mint_cap_per_epoch` for that class is invalid, because the denominator is missing.
9. **Scope classes encoding.** `scope_classes` is an object, a map from class name to class policy object. That is the only conforming form; a list form is non-conforming.
10. **Ceiling curve encoding.** `ceiling_curve` is an array of tier objects, each carrying integer fields `min_standing` and the six ceiling outputs of Section 16.3, item 3. Two tiers may not share a `min_standing`, and the first tier must have `min_standing` 0 (the entry tier). Every ceiling field is non-decreasing as `min_standing` increases. The tier in force for a Standing value is the tier with the greatest `min_standing` not exceeding it.
11. **Countersign weight.** Where the `countersign_policy` does not require a countersignature for a class, a completed, in-ceiling action mints at full weight whether or not it is countersigned. Where it does require one, an uncountersigned action mints zero (invariant I4). There is no reduced-weight tier in v0.1.
12. **Burns do not decay.** Decay under decision 4 applies to mint events only, and a burn applied in a segment stands for the whole segment.
13. **Inheritance reserved.** Inheritance is out of v0.1 scope. The policy field `inheritance_factor_ppm` (an integer in parts per million, at least 0 and below 1,000,000) is reserved: it is parsed, carried, and hash-committed with the policy, and consumed by no v0.1 computation. No v0.1 receipt or charter event carries an inheritance; a charter forked in v0.1 starts at zero in every class, which satisfies the "at most" bound of invariant I3. The inheritance event and its computation are v0.2 work.
14. **Standing scale.** Standing is an unbounded non-negative integer, by decision. All Standing arithmetic is checked arithmetic: an overflow is an error, never a wrap. The fixed 0 to 1,000,000 scale proposed in the engineering blueprint is not adopted; ceilings, not the Standing integer, are where a charter bounds authority.
15. **Witness policy encoding.** `witness_policy` is the object `{witness_key_ids: [witness key identifier strings], quorum: k}`, where k is an integer with 1 <= k <= the number of listed witness key identifiers. That is the only conforming form.
16. **Countersigned outcome descriptor (amendment, 2026-11-23, repair round 3).** The bytes a counterparty countersignature covers are fixed here, because the second re-audit found the two reference implementations signing different bytes under a written claim of byte-identity. The descriptor is the canonical JSON encoding (object keys sorted, no insignificant whitespace, UTF-8) of exactly this object, no more and no fewer fields: `agent_id` (string), `action_name` (string), `arguments_hash` (string or null), `receipt_id` (string or null), `result_hash` (string or null), `risk_weight` (integer or null), `scope_class` (string), `timestamp` (integer seconds). A field a receipt does not carry is encoded as null. The signature is computed over the DSSE Pre-Auth-Encoding of the payload type `application/vnd.acta.counterparty-outcome.v0.1+json` and these exact bytes. Any implementation whose descriptor differs in a field name, a field's presence, or the serialisation does not implement invariant I4, whatever its other behaviour.
17. **Kill-subtree field name (amendment, 2026-11-23, repair round 3).** A KILL-BURN receipt names the agents it burns, beyond its own agent, in exactly one field: `killed_agent_ids`, a list of agent identifier strings. On a prototype-format (JSON) receipt the field is top-level; on a native receipt it is the verdict-map key of the same name. That is the only conforming name in either transport. A computation that reads any other name, or that drops the list on any transport, does not implement Section 16.6.
18. **Diversity caps placement (amendment, 2026-11-23, repair round 3).** The `diversity_caps` object of decision 8 lives at the top level of `standing_policy` only, beside `scope_classes`. A `diversity_caps` object inside a scope class is non-conforming, and a conforming implementation must reject it at policy validation or parsing, never silently honour it in one implementation and silently ignore it in another. The differential evidence for this decision: the per-class form produced different Standing for the same policy in the two reference implementations, with no error on either side.
19. **Descriptor context (position recorded, 2026-11-23).** The descriptor of decision 16 binds receipt content: agent, action, scope class, timestamp, risk weight, and the receipt's identity and hashes. It does not bind a chain head, a charter hash, or an organisation identifier, so identical receipt content on a second chain accepts the same countersignature. For v0.1 this is accepted and stated, not silently left open: a countersignature attests that the named counterparty bore the risk of that outcome, identified by its content, and receipt identities are unique within a chain (a chain carrying two receipts with one `receipt_id` is invalid and must be rejected at verification). Binding countersignatures to a chain or organisation is v0.2 work, to be decided with the inheritance event of decision 13.
20. **Authorised key rotation (position recorded, 2026-11-23).** Under Sections 6.3 and 6.5, an amendment signed by a currently authorised key may replace `amendment.authorized_key_ids`, rotating who may amend. The pinned founder anchor is therefore a one-generation anchor unless the founder freezes the field: a founder who wants founder-only amendment for the life of the charter declares `amendment` itself in `frozen_fields`, as the shipped example charters now do. Rotation is authorised delegation, not a defect; leaving it unfrozen without knowing this sentence is the defect, and charter tooling should say so.
21. **Ceiling curve placement (amendment, 2026-11-23, repair round 3).** The `ceiling_curve` of decision 10 is stated at the top level of `standing_policy`, as Section 16.3 item 3 lists it among the policy's contents. A scope class may state its own `ceiling_curve`, which overrides the policy-level curve for that class. Both placements are conforming, both are honoured, and the override rule is identical in every implementation: class curve where stated, policy curve otherwise, an error where neither is stated and ceilings are produced. What is non-conforming is the pre-amendment state, in which one implementation honoured the per-class form and the other had never been asked.
22. **Countersign requirement encoding (amendment, 2026-11-23, repair round 4).** The requirement that a scope class mint only with a counterparty countersignature (invariant I4, decision 11) is switched on by exactly one field, in exactly one form: the top-level `standing_policy` field `countersign_policy`, an object of the form `{"required_for": ["write"]}`, where `required_for` is an array of scope class name strings, and it is the only key the object may carry. A class named in `required_for` requires a countersignature; a class not named does not; an absent `countersign_policy` requires none anywhere. Every other shape is a policy validation error in every conforming implementation, never silently honoured and never silently ignored: a bare boolean or bare array as the value of `countersign_policy`, an object carrying any other key (a per-class boolean map, a `classes` list, or any other inner form), a non-string entry in `required_for`, the field stated inside a scope class, and any differently named field stating the same intent (including `countersign_required`, at policy level or inside a class). The third re-audit's evidence for this decision: the two reference implementations each read a different encoding of this requirement and silently ignored the other's, so the same charter minted at full weight in one tree and at zero in the other, with no error on either side. The signature bytes were unified by decision 16; this decision unifies the switch that makes them mandatory.
23. **Ceiling curve requirement (amendment, 2026-11-23, repair round 4).** `ComputeStanding` returns, by Section 16.1, a Standing vector and the authority ceilings that vector implies: producing ceilings is part of the computation's result, not a separate operation a caller may skip. The tail of decision 21 therefore applies uniformly: where neither the class nor the policy states a `ceiling_curve` (decision 10's encoding, decision 21's placement), the computation stops with an unspecified-by-policy error, in every implementation, identically. A policy that states no curve anywhere is an incomplete policy, not a policy whose ceilings are absent from an otherwise valid result.
24. **The strictness table (amendment, 2026-11-23, repair round 5).** One acceptance surface governs every policy and receipt scalar in both reference implementations, because the fourth re-audit found the two trees agreeing on all Standing arithmetic for well-formed inputs and diverging only on which malformed inputs each parser accepts. The table is normative, and every row is a validation or parse error in every conforming implementation, never a coercion, a clamp, a default, or a silent drop:
    (a) **Integer where the specification says integer.** Every scalar a decision of this subsection fixes as an integer (policy quantities, rates, caps, multipliers, weights, epoch and half-life lengths, parts-per-million fields, ceiling tier fields, receipt `risk_weight`, `delegation_depth`, and `burn_amount`, and every timestamp) is an integer or the input is malformed. Booleans, floats, and strings in those positions are errors, including float and string timestamps: a timestamp is an integer number of seconds or the receipt is malformed.
    (b) **Non-negative where the field is a quantity.** Every quantity, rate, cap, multiplier, weight, and timestamp is non-negative or the input is malformed. A negative value is never computed with: in particular a negative `burn_unit` or burn multiplier is an error, because a negative burn would manufacture Standing.
    (c) **Non-null where a field is stated.** A field stated with a null value is a malformed value, never an absent field, for every policy field, class field, and receipt scalar, including `countersign_policy` and `witness_policy`. Absence is expressed only by omitting the field.
    (d) **Spec-named only.** A field is read under the name this specification gives it and no other. Undocumented aliases are rejected, never honoured and never silently dropped where they carry intent: the severe reason codes field is `severe_reason_codes` (decisions 1 and 2 and invariant I5), and the name `severe_codes` is non-conforming in every implementation. The aliases the specification itself documents remain conforming exactly as documented: `half_life` for `half_life_seconds` (decision 4) and a bare `hop_attenuation` of the integer 1 (decision 6).
    (e) **Eager, complete, class-local parsing.** A policy is parsed completely when it is loaded, before any computation: every class in `scope_classes` is parsed and validated whether or not the computation touches it, and a malformed value anywhere in the policy is an error before any Standing is computed. Class fields are read from the class object only: a field stated at the top level of `standing_policy` never merges into a class. The fields the decisions place at policy level (`epoch_seconds`, decision 3; `ceiling_curve`, decision 21; `diversity_caps`, decision 18; `countersign_policy`, decision 22; `witness_policy`, decision 15) are read there and only there. A malformed `witness_policy` is an error at computation entry as it is at checkpoint verification, and decision 15's quorum bounds (1 <= quorum <= the number of listed witnesses) are checked wherever the policy is parsed, validated, computed under, or verified against.
    Where an earlier decision's wording conflicts with this table, this decision governs: decision 22's silence on whether a stated null is absent or malformed is resolved by row (c) (malformed), and any implementation behaviour the fourth re-audit recorded as reading a stated null as absent, inheriting a top-level field into a class, validating a policy lazily, or honouring the `severe_codes` alias is superseded.

## 17. Conflicts among the source reports, and their resolutions

Recorded so engineering seats are never handed two incompatible instructions:

1. Builder capacity. The Acta founding report and the programme report were written for a solo builder (the programme report models a roughly 20-hour week and a two-repository ceiling). The firm-scale report supersedes both on this point, on the founder's explicit correction. Resolution: this plan uses firm-scale staffing (Sections 1.4, 9), keeps the programme report's architecture and sequencing logic, and converts its solo allocation percentages into effort shares rather than one person's hours.
2. Signing. The Acta founding report specified canonicalised JSON receipts. The programme report flagged that in-toto and DSSE deliberately sign exact bytes in a typed envelope and criticise canonical-JSON signing. Resolution: DSSE-style typed envelopes win (Section 2.2). The founding report's receipt fields are preserved unchanged; only the signature construction changed.
3. Repository count and programme shape. The founding report had Acta with ToolGate as an adapter inside its story; the programme report fixed shape B, two repositories, shared core, Acta first; the firm-scale report made the Constitution Layer the successor form. Resolution: three repositories on the same shape B logic, Acta specification first, dependency arrows unchanged in direction (Section 8).
4. Acta's position. The founding report made Acta the headline ambition; the firm-scale report demoted it to an evidence sub-layer of Institutio. Resolution: Acta keeps its own one-liner, repository, and gates, and remains the layer everything else depends on. Institutio is the successor form and the public ambition; Acta is the foundation. Both statements are kept because both are load-bearing: a constitution without receipts is unenforceable, and receipts without a constitution are unauditable.
5. Gates. The founding report's Acta gates (3 external repositories at 90 days) and the programme report's revised gates (2 external receipt producers or 300 foreign bundles) differ. Resolution: the programme report's numbers govern, extended with the Institutio pilot condition (Section 10.1).
6. Forcing function. The founding report anchored adoption to the merge and approval chokepoints and warned against depending on future law; the firm-scale report leaned on the EU AI Act duties. Resolution: both, in that order of reliance. Chokepoints the programme controls come first (Section 11.2); the dated statutory duties are the second engine, and they are enacted law with fixed dates, not hoped-for law.
7. The Provable Kill fold-in (added 2026-11-23, after the original synthesis). A fourth source report, the instant fame and genius capability report of the same date, scored seven candidate demonstration capabilities and named the Provable Kill the winner (22 of 25). Folding it in changed this document in five recorded ways, each a resolution of a tension with the earlier text. (a) Demonstration centrepiece: Sections 8.4 and 8.5 of the pre-fold draft made the publicly constituted firm, and a poisoned-tool demonstration, the launch story. The fame report scored the Public Firm at 16 of 25 as a claim, on un-fakeability grounds. Resolution: the firm is the stage, the kill is the claim (Sections 7.5, 9.5). (b) Denial receipts: the earlier sections required deny receipts as verdict records (Section 3.5). The fame report showed that a revocation demonstration needs them as a first-class, reason-coded receipt type, or it proves only silence. Resolution: Section 3.5 extended, and ticket T2 of Section 7.3 flags the change as the most important in the fold-in. (c) The second implementation: Section 6.1 required a second implementation from a separate internal workstream. Ticket T9 strengthens this for the verifier specifically: the second verifier must be built by a stranger from the specification alone, before launch, with the write-up published unedited. (d) Launch success: the pre-fold draft treated the launch event itself as the deliverable. Resolution: the launch is a precondition-gated event (Section 10.1), and its success criterion sits at launch plus 30 days: the first non-founder constituted organisation verifying publicly, measured by the independent-verification counter (Sections 9.6, 10.1, Annex A). (e) Claims discipline: no earlier report constrained what the founder may say publicly. Resolution: Annex A is normative, and where any earlier draft language in this document conflicts with it, Annex A governs.
8. The Standing fold-in (added 2026-11-23, after the Provable Kill fold-in). A fifth source report, the game-changing mechanism report of the same date, prior-art-checked ten candidate mechanisms and named Receipt-Minted Authority (Standing) the winner as a novel combination, every atom having close prior art. Folding it in forced five recorded resolutions. (a) The grounds of the kill: Sections 7, 9.5, and 10.1 previously stated revocation as the kill's sole ground. The mechanism report showed the kill is stronger, and harder to stage or to dismiss, with a second independent ground. Resolution: Standing is the kill's second ground everywhere its grounds are stated, the KILL-BURN checkpoint is ticket T11 of Section 7.3, and `standing-ceiling` joins the v0.1 denial reason codes in Section 3.5. (b) The meaning of a grant: Sections 5 and 6 previously treated a charter grant plus manifest checks as sufficient for an action to proceed. Resolution: they are necessary and not sufficient; effective authority is the minimum of grant, manifest, and Standing ceiling (Sections 5.1, 6.4, 16.1). (c) Probabilities: Section 15 previously carried the firm-scale report's Institutio odds. The mechanism report revised them upward on the strength of the forced-reader argument. Resolution: the revised figures govern in Section 15, with the superseded figures recorded there and the speculation label unchanged. (d) The insurer's position: Section 11 previously named insurers as future customers approached after the gates. Resolution: insurers are the programme's first forced reader, and the priced pilot of Section 16.8 is scheduled post-launch work with its dataset and witness hooks inside the 90-day plan; the pilot itself is not in the 90-day build core. (e) Novelty language: no earlier section claimed novelty for any mechanism. Resolution: Section 16.2 states the claim as combination-only, with the nearest prior art named, and Annex A governs any public restatement of it.
9. The Section 16 encoding gaps (added 2026-11-23, after the Standing fold-in). Building institutio-core against Section 16 produced fifteen places where the section named a mechanism but fixed no encoding or parameter: the burn base, the burn closed form, the epoch, the half-life field and discretisation, the evaluation time, the hop attenuation encoding, the correlated burn fraction, the diversity cap denominator and missing subtree field, the scope classes and ceiling curve encodings, the countersign weight, whether burns decay, the inheritance event, the Standing scale, and the witness policy encoding. The gaps came from the institutio-core build; they are now closed. Resolution: Section 16.10 decides all fifteen as normative text, adopting the crate's documented behaviour where it was already spec-compatible and the engineering blueprint's integer forms where the crate had none, and institutio-core was then brought into line with the amended text. Two consequences are recorded for honesty. Fixture 11 of the prototype corpus passed as prototype-parameter conformance only at the time of this note, because its policy as written omitted fields the amended specification requires the policy itself to state; repair round 3 completed that policy (finding S3), and fixture 11 now passes as spec conformance in both runners. Fixture 14 passes as spec conformance, and the half-life caveat formerly attached to it is withdrawn, because Section 16.10, decision 4, now fixes the field name, unit, and discretisation it uses.
10. The composition gaps (added 2026-11-23, after repair round 3). The second independent re-audit found the two reference implementations diverging between mechanisms while each was faithful inside its own: the countersigned descriptor was different bytes in the two trees under a written claim of byte-identity, the kill-subtree list travelled under three field names and was dropped on one transport, the Python computation silently defaulted policy values Section 16.10 requires it to stop on, the Python checkpoint quorum read a field name (`min_cosigs`) this specification never defined, and per-class `diversity_caps` bound in one tree and were silently ignored in the other. Resolution: Section 16.10 gained decisions 16 to 21, fixing the descriptor's exact field list and serialisation, the single kill-subtree field name `killed_agent_ids`, the policy-level-only placement of `diversity_caps` with rejection of the per-class form, the ceiling curve placement and override rule, and recorded positions on descriptor context and authorised key rotation. Both implementations were brought to the amended text in repair round 3, and the cross-implementation differential test now exercises countersigned chains with a real counterparty key map and a named-child subtree kill, the two cases whose absence hid the divergence.
12. The strictness gaps (added 2026-11-23, after repair round 5). The fourth independent re-audit ran a 130-case differential campaign and found the one definition true for completely stated, specification-form policies (103 cases in exact agreement, and every mechanism case agreeing), with all 27 divergences at the acceptance surface: the Python parser accepted negative policy integers its sibling rejected, and a negative burn manufactured Standing in it; the Python policy parse was lazy and inherited top-level fields into classes while the Rust parse was eager and class-local; each tree read a stated null as absent for a different set of fields; a malformed witness policy was invisible to the Python computation and a parse error in Rust, with quorum bounds checked at different doors in each tree; a non-string receipt identity was silently erased by the Rust prototype parser; a null risk weight defaulted in Rust and errored in Python; float and string timestamps coerced in one tree and zeroed in the other; and the Rust tree honoured an undocumented `severe_codes` alias. Resolution: Section 16.10 gained decision 24, one strictness table (integer, non-negative, non-null, spec-named, eagerly and class-locally parsed) stated as normative text and implemented identically in both trees, and the re-audit's divergent cases were added to the differential suite as permanent cases. Where decision 24 and an earlier decision's wording conflict, decision 24 governs, as it records.
11. The convergence gaps (added 2026-11-23, after repair round 4). The third independent re-audit found the one definition holding for completely stated, specification-form policies, and failing at two surfaces the round 3 amendments had not reached: the countersign requirement was switched on by a different field name in each implementation, each silently ignoring the other's form (finding T1), and the Rust tree accepted duplicate receipt identities at verification and at computation although decision 19 makes uniqueness normative, while its README claimed the opposite (finding T2). Resolution: Section 16.10 gained decision 22, fixing the one conforming encoding of the countersign requirement (the `countersign_policy` object with a `required_for` list, the field Section 16.3 item 4 already names) and making every other shape a validation error in both implementations, and decision 23, fixing the ceiling curve as a required field wherever ceilings are produced, so a policy stating no curve errors identically in both trees. Decision 19's duplicate rule is now implemented in the Rust tree as it already was in the Python tree. The same round aligned the residues the re-audit graded minor: negative tally and weight values are validation or parse errors in both trees, the Python policy parser rejects boolean and float values where integers are required as the Rust parser does, malformed witness policies are errors in both trees, the Python prototype's legacy alias encodings (which no other implementation read) are retired so the accepted policy language is identical, the decisions of Section 16.10 stand in numeric order in the document, and Section 16.3 cross-references decisions 21 and 22.

## Annex A. Claims ceiling (normative)

Source: the instant fame and genius capability research report dated 2026-11-23. This annex binds every public statement made for the programme: posts, talks, interviews, repository pages, and the launch materials. Where any other text conflicts with this annex, this annex governs (Section 17, conflict note 7).

### A.1 What may be claimed

Public claims may be made only in receipt-anchored, dated, file-backed forms. The permitted shapes are:

1. "On [date], a delegation in a live organisation was revoked, and here is a file that lets you verify the consequences offline."
2. "[N] receipts have been verified by verifiers we do not control. The inputs to that counter are public."
3. "Institutio v0.1 specifies a charter, delegations that only ever attenuate, and a kill switch with receipted effect. It does not make agents safe, honest, or competent."
4. "Our firm runs under this charter. That is evidence the system operates at our scale, not evidence it will work at yours."
5. "Here is our failure log. It is part of the product."

A claim in any other shape must be reducible to one of these forms, with its date and its file named, before it is published.

### A.2 What must never be claimed

1. Never "unhackable", "provably safe", "trustless", "guaranteed", or "solves agent security", in any paraphrase.
2. Never a headcount claim ("10,000 employees", "the world's largest agent company", or any equivalent) without the published definition of what counts as an agent and the receipt-derived activity distribution attached at the moment the number is spoken.
3. Never a counterfactual as fact. "ToolGate would have blocked incident X" may be published only as labelled inference, with the manifest or scope analysis shown. The Autopsy of Section 9.6 is bound by this rule in every paragraph.
4. Never "first" (first constitution for agents, first receipt format, or any equivalent) unless a prior-art search is published alongside the claim.
5. Never any number whose raw inputs are not public at the moment the number is spoken.
6. Never that the Provable Kill proves real-world attackers will behave as the rogue fixture behaves. It proves the authority mathematics of revocation, attenuation, and denial (Section 7.4), and claims stop there.

### A.3 Loud surface, frozen surface

1. The loud surface may change daily: the demonstration, the ledger explorer, the counter, the failure log, essays, and the rogue-agent theatre. Nothing on the loud surface is normative, and every public use of a programme slogan links to a bundle that verifies.
2. The frozen surface changes only by hash-chained amendment with versioned releases: the `institutio.json` schema, the Acta receipt format, the ToolGate manifest format, and verifier semantics. The launch materials state the freeze explicitly and link the v0.1 hashes. If public attention demands a specification change, the answer is a versioned amendment event, publicly receipted, never a quiet edit.
3. The danger metric, reviewed weekly during and after the launch window: the ratio of loud-surface changes to frozen-surface amendments. If the loud surface is consuming the programme, fame is eating the artifact, and the correction is to cut loud-surface work, not to unfreeze the core.

### A.4 The fame KPI that counts

The headline KPI is independent verifications by non-founder parties (Section 9.6), and behind it, non-founder constituted organisations. These are fame converted into adoption. Hacker News points, repository stars, video views, press mentions, agent headcount, and receipts issued are vanity metrics: they may be recorded internally and are never published as success.
