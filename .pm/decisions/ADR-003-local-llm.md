# ADR-003: Optional local LLM

- Status: accepted (Özer, 2026-11-11), implementation in Phase 4

## Context
LLM triage and fix explanations reduce noise, but sending findings/code to hosted LLMs breaks "nothing leaves the machine".

## Decision
Off by default. When enabled, bastion talks only to an OpenAI-compatible endpoint on localhost (default Ollama `http://127.0.0.1:11434/v1`). Non-loopback endpoints are refused. All target-derived content is passed as clearly delimited untrusted data; model output is advisory and never triggers actions without user confirmation.

## Consequences
- No new external network call.
- Prompt-injection tests (incl. BLA-hardened artifacts) are part of Phase 4 exit.
