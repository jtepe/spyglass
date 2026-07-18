# Spyglass documentation

Auxiliary documentation for Spyglass. The top-level [`README.md`](../README.md)
covers usage and the Audit Report; [`CONTEXT.md`](../CONTEXT.md) defines the
domain terms. This directory holds the longer-form references behind those.

Graphics referenced from these docs live under [`../assets`](../assets).

## Contents

- [Directory roles and service principals](service-principal-directory-roles.md)
  — the direct, via-group, and PIM paths by which a Service Principal can hold a
  Directory Role, and why an *eligible* assignment is impossible for one.
- [Required permissions, in detail](permissions.md) — the least-privileged
  permission set per plane, derived call-by-call from the Graph and ARM
  queries the tool makes.
- [The Run Store](run-store.md) — the SQLite database behind `--db`: the
  per-run snapshot schema, its timestamp semantics, and how to query change
  history with plain SQL.
