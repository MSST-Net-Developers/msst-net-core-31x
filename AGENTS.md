# MSST-Net 3.1.x

## 0. Mission

You are working on MSST-Net 3.1.x.

MSST-Net is a private virtual networking system designed primarily for:
- private LAN / virtual LAN networking
- Minecraft and game networking
- private servers
- small trusted networks
- long-running self-managed services

The 3.x architecture separates Core and Controller.

Your primary goal in 3.1.x is NOT to add as many features as possible.

The primary goal is:

> Make MSST-Net Core predictable, observable, recoverable, and maintainable.

Do not turn this task into a large-scale rewrite unless the existing architecture makes the target design impossible.

Preserve working functionality whenever possible.

---

# 1. Existing high-level architecture

MSST-Net 3.x consists of two major components:

## Core

Core is the privileged networking daemon/process.

Core owns:

- network state
- node state
- connection state
- path selection
- networking operations
- ACL evaluation
- reconciliation
- recovery
- system-level side effects

Core is the authoritative source of truth.

## Controller

Controller is an unprivileged client.

It provides:

- GUI
- user interaction
- state presentation
- commands to Core
- diagnostics

Controller MUST NOT directly manipulate networking state.

Controller communicates with Core through IPC.

Examples of IPC transports:

- Linux: Unix domain socket
- Windows: Named Pipe
- potentially localhost TCP or another transport in the future

The IPC transport must be separated from the IPC protocol.

---

# 2. Fundamental architectural rule

Core owns truth.

IPC transports commands, state and events.

Controller presents state and requests operations.

The intended architecture is:

Controller
|
| IPC
v
Core
|
+-- State
+-- Policy / ACL
+-- Network
+-- Reconciliation
+-- Recovery
+-- Effects
|
v
Operating System / Network

Do NOT introduce business logic into Controller merely because it is convenient.

Do NOT let Controller directly modify:
- WireGuard
- routes
- sockets
- firewall state
- node state
- connection state
- path state

All such operations must ultimately be controlled by Core.

---

# 3. Core design principles

## 3.1 Core is the single decision authority

There must be one authoritative Core state.

Avoid multiple independent state machines in:
- GUI
- Controller
- network modules
- background tasks

Controller may cache/display state, but it must not become another source of truth.

---

## 3.2 Desired state vs observed state

Where appropriate, distinguish:

- Desired State
- Observed State

Example:

Desired:
Peer A should be connected

Observed:
Peer A is currently disconnected

This should be represented as a recoverable state discrepancy rather than being hidden inside arbitrary callbacks.

The system should be able to reconcile:

desired != observed
->
reconciliation
->
effect
->
observe
->
verify

---

## 3.3 State transitions must be explicit

Prefer:

(State, Event) -> (NewState, Effects)

rather than scattering state mutations across asynchronous callbacks.

Important state domains may include:

- Node
- Connection
- Path
- Service
- ACL
- Authentication/session state

Do not create one giant enum that attempts to represent the entire system state.

Prefer orthogonal state dimensions where appropriate.

---

## 3.4 Side effects must be separated from decisions

Core logic should determine WHAT should happen.

Effect executors should perform HOW it happens.

Example:

Decision:

    ConfigurePeer(node_id)

Effect executor:

    actually configure WireGuard

The decision layer should be testable without requiring real network interfaces.

---

## 3.5 Asynchronous operations must not corrupt newer state

Use generation/version/epoch mechanisms where appropriate.

Example:

Generation 42:
connect node A

Generation 43:
disconnect node A

If an old task from generation 42 finishes after generation 43,
its result MUST NOT overwrite the newer state.

Do not assume asynchronous operations complete in the same order they were started.

---

## 3.6 Recovery must be explicit

Avoid independent uncontrolled retry loops throughout the codebase.

Recovery should be:

failure
->
classify
->
retry / backoff / reconnect / rebuild
->
verify
->
success / degraded / failed

Retries should be bounded or otherwise explicitly controlled.

---

# 4. IPC architecture

IPC is a first-class architecture component.

Do not treat it as a thin implementation detail.

Separate:

1. IPC protocol
2. IPC transport
3. Core IPC server
4. Controller IPC client

Conceptually:

IPC Protocol
|
+-- Request
+-- Response
+-- Event
+-- Error
+-- Versioning
|
Transport
|
+-- Unix Socket
+-- Windows Named Pipe
+-- future transports

The protocol should not depend on Unix sockets specifically.

---

# 5. IPC semantic model

IPC should support at least three categories.

## Query

Used to obtain current state.

Examples:

- GetSystemState
- GetNodes
- GetNode
- GetConnections
- GetPaths
- GetACL
- GetDiagnostics

## Command

Used to request an operation.

Examples:

- ConnectNode
- DisconnectNode
- CreateACLRule
- DeleteACLRule
- CreateRoom
- LeaveRoom

A successful command response means:

> Core accepted the command.

It does NOT necessarily mean that the final operation has completed.

For example:

ConnectNode
->
accepted

Then:

NodeConnecting
->
Handshake
->
PathEstablished
->
NodeConnected

The Controller should receive state changes through events.

## Event

Core-generated notifications.

Examples:

- NodeAdded
- NodeRemoved
- NodeStateChanged
- ConnectionStateChanged
- PathChanged
- ACLChanged
- AccessRequestCreated
- DiagnosticEvent

---

# 6. Snapshot + Event Stream

Controller should be able to recover after restart.

Preferred lifecycle:

1. Controller connects to Core.
2. Controller requests an initial snapshot.
3. Controller subscribes to events.
4. Controller renders the snapshot.
5. Controller applies subsequent events.

Core must continue functioning if Controller is closed.

When Controller reconnects, it should be able to reconstruct current state from Core.

Do not make Core dependent on the lifetime of Controller.

---

# 7. IPC security

Core is privileged.

Therefore IPC access must be authenticated/authorized appropriately.

On Linux, consider:
- Unix socket permissions
- peer credentials
- UID/GID
- appropriate privilege separation

Do not assume that possession of the socket path automatically grants permission to execute arbitrary Core operations.

Do not weaken OS-level privilege boundaries merely to simplify development.

---

# 8. ACL model

MSST-Net currently supports INBOUND ACL rules.

A rule conceptually matches:

    Source Device
    +
    Destination Protocol / Port Group

A rule may contain:

- multiple source devices
- multiple destination protocol/port groups
- allow or deny action

Users may select predefined service templates.

Users may also manually define protocol/port groups.

For example:

Minecraft Java
TCP / 25565

or custom services such as:

TCP / 1234
UDP / 5000-5010

---

# 9. ACL identity model

MSST-Net has:

- User ID: UUID
- User mnemonic
- Device ID: UUID
- Device mnemonic
- Device composite mnemonic, e.g. pc.abjust
- Display name

Persistent ACL rules should use stable UUIDs rather than display names or mnemonics.

Mnemonics and display names are presentation / resolution mechanisms.

If a mnemonic or display name changes, an existing ACL rule should not silently change its identity.

---

# 10. ACL scopes and priority

Current intended rule priority:

Device-level DENY
>
Device-level ALLOW
>
User-level DENY
>
User-level ALLOW
>
Default policy

Default policy is:

DENY unmatched inbound traffic.

This is a default-deny security model.

There is also a design principle:

> More specific rules take precedence over broader rules.

The exact comparator between specificity and deny/allow precedence MUST be formalized in code and tests.

Do not invent a new priority interpretation without discussing it.

If existing implementation already defines this behavior, preserve it unless there is a documented reason to change it.

---

# 11. ACL explainability

ACL decisions should ideally be explainable.

A decision should be capable of answering:

- What source matched?
- What service matched?
- Which rule matched?
- What scope did the rule have?
- Why did the rule win?
- Was the final decision ALLOW or DENY?

Prefer returning structured decision information rather than only:

    true / false

Conceptually:

Decision {
action,
matched_rule,
reason,
priority
}

This information will later be used by Controller diagnostics.

---

# 12. Authentication

MSST-IAS provides authentication/identity services.

Authentication is primarily an access/control-plane concern.

Do NOT make normal data-plane networking depend on continuous IAS availability unless explicitly required.

The intended model is approximately:

Authentication
->
identity / authorization information
->
MSST-Net Core
->
independent network operation

Do not rewrite MSST-IAS as part of 3.1.x unless explicitly requested.

---

# 13. Product modes

MSST-Net has two important user-facing modes.

## Room mode

Designed for:
- friends
- temporary networking
- Minecraft/game sessions

Unauthenticated users may use room mode with limitations.

Current intended limitation:
- unauthenticated room: maximum 5 participants

Authenticated users can use larger/unlimited room mode.

Room mode supports interactive authorization and game discovery mechanisms.

## Large LAN mode

Designed for:
- home servers
- persistent services
- self-managed private networks

It uses user-configured ACL policies.

When not participating in a room, this mode is the default model.

Do not redesign these product semantics without explicit instruction.

---

# 14. Current networking concepts

Existing MSST-Net 3.x concepts include:

- node table
- dynamic path management
- private IPv4 addressing
- private IPv6 ULA addressing
- WireGuard/boringtun-related networking
- STUN/NAT traversal
- discovery proxy
- service discovery
- DNS
- game discovery

Do not assume that every mechanism needs to be rewritten.

First inspect the existing implementation.

---

# 15. Important architectural distinction

Service discovery and authorization are separate concepts.

The fact that a device can discover a service does NOT imply that it has permission to access it.

For example:

Service discovered:
Minecraft TCP/25565

ACL decision:
DENY

Result:
service exists, but access is blocked.

Do not accidentally couple discovery with authorization.

---

# 16. Development methodology

Before modifying code:

1. Inspect the repository.
2. Identify the current architecture.
3. Identify Core/Controller boundaries.
4. Identify IPC implementation.
5. Identify state ownership.
6. Identify asynchronous tasks.
7. Identify networking side effects.
8. Identify existing tests.
9. Identify existing behavior that must be preserved.
10. Produce a short architecture assessment.

DO NOT immediately start rewriting files.

---

# 17. Change policy

Prefer incremental refactoring.

For every significant architectural change:

1. Explain the current problem.
2. Explain the proposed solution.
3. Identify affected modules.
4. Identify compatibility risks.
5. Implement the smallest coherent change.
6. Run tests/build.
7. Inspect the result.
8. Continue to the next change.

Do not perform a giant rewrite of the repository in one step.

---

# 18. Preserve behavior

Unless explicitly instructed otherwise:

- preserve existing public behavior
- preserve working network functionality
- preserve protocol compatibility where practical
- preserve existing configuration formats where practical
- avoid unnecessary API changes
- avoid unnecessary dependency changes

If an existing behavior conflicts with the new architecture, document it before changing it.

---

# 19. Testing requirements

Important pure logic should have deterministic unit tests.

Especially test:

- state transitions
- ACL matching
- ACL priority
- specificity
- UUID resolution
- generation handling
- reconciliation decisions
- IPC serialization/deserialization
- IPC request/response semantics
- event ordering where applicable

Network integration tests should be separated from pure logic tests.

---

# 20. Non-goals for 3.1.x

Do NOT expand scope unnecessarily.

Avoid:

- unrelated GUI redesign
- unnecessary authentication redesign
- adding many new networking protocols
- building a plugin ecosystem
- adding social features
- large-scale feature expansion
- rewriting stable networking code without a concrete reason

3.1.x is primarily a stabilization and architecture-convergence release.

---

# 21. Definition of Done

3.1.x should eventually satisfy:

## Core

- Core owns authoritative state.
- Controller cannot directly manipulate network state.
- State transitions are explicit.
- Async tasks cannot overwrite newer state.
- Desired and observed state can be reconciled.
- Recovery is explicit and bounded.
- Important decisions are observable.

## IPC

- Protocol is explicitly defined.
- Transport is separated from protocol.
- Request/response/event semantics are explicit.
- Controller can reconnect.
- Controller can reconstruct state from Core.
- Core remains functional without Controller.
- IPC privilege boundaries are enforced.

## ACL

- Inbound rules work.
- Default deny works.
- Device-level rules work.
- User-level rules work.
- Multiple source devices work.
- Multiple service groups work.
- Custom protocol/port groups work.
- UUIDs are used as persistent identity.
- Priority is deterministic.
- Decisions are explainable.

## Reliability

A network failure should produce a diagnosable state rather than an unexplained failure.

---

# 22. Agent behavior rules

You are an implementation agent, not the architect of the project.

You may propose improvements.

You MUST NOT silently change architectural semantics.

If you encounter ambiguity involving:

- ACL semantics
- IPC protocol semantics
- identity semantics
- authentication semantics
- network protocol compatibility
- persistent data formats

STOP and ask for clarification rather than inventing behavior.

For small implementation details, use reasonable engineering judgment.

For architectural decisions, ask.

---

# 23. First task

DO NOT modify the code immediately.

First:

1. Inspect the entire repository structure.
2. Locate Core.
3. Locate Controller.
4. Locate IPC implementation.
5. Identify IPC transport(s).
6. Identify IPC message definitions.
7. Identify Core state representation.
8. Identify networking side-effect boundaries.
9. Identify ACL implementation.
10. Identify existing tests.
11. Identify architectural inconsistencies.
12. Produce an implementation plan for MSST-Net 3.1.x.

The first response after inspection should contain:

A. Current architecture
B. Current Core/Controller boundary
C. Current IPC design
D. Current state-management model
E. Current ACL model
F. Problems discovered
G. Proposed 3.1.x migration plan
H. Files/modules that would be modified
I. Risks
J. Testing plan

Do not implement the migration until the plan has been reviewed.