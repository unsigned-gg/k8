<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Architecture Specifications (LeanSpec)

> Specifications precede implementation. If a system's invariants cannot be
> articulated in plain technical English, compiling it is merely executing an
> unvetted guess.

This directory is the LeanSpec registry of record for `k8`. Every architectural
decision, boundary rule, and verification gate is specified as an individual,
versioned contract.

| Spec | Title | Status | Priority |
|---|---|---|---|
| [SPEC-0001-k8-architecture-and-roadmap.md](./SPEC-0001-k8-architecture-and-roadmap.md) | k8 Architecture, Operational Invariants & Multi-Horizon Roadmap | complete | critical |

## Specification Lifecycle

- `planned`: Under architectural evaluation.
- `in-progress`: Implementation or formal verification active.
- `complete`: Implemented with verified test suites and operational gates.
- `archived`: Deprecated or superseded.

## Specification Standard (EARS)

All specifications follow Easy Approach to Requirements Syntax (EARS):
- **Ubiquitous:** `The <system> shall <action>`
- **Event-driven:** `WHEN <event>, the <system> shall <action>`
- **State-driven:** `WHILE <state>, the <system> shall <action>`
- **Unwanted behavior:** `IF <error>, THEN the <system> shall <action>`
- **Optional feature:** `WHERE <feature>, the <system> shall <action>`
