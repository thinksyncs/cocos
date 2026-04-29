# Attestation Binding Review Layers

This note defines a small review aid for Cocos aTLS and attestation discussions.
The L0-L5 labels below are not Cocos protocol terminology. They are used here to
separate channel binding, evidence binding, platform appraisal, deployment
identity, workload identity, and authorization questions during review.

This is a design note, not a production bug claim.

## Layer summary

| Layer | Review question | Cocos mechanisms to inspect |
| --- | --- | --- |
| L0 | Is the accepted peer on the expected live TLS channel? | TLS 1.3, certificate validation, Exported Authenticator CertificateVerify / Finished validation |
| L1 | Is attestation evidence or authenticator material bound to that TLS channel? | request context, TLS exporter binder, exporter label, leaf public key, evidence nonce / report data |
| L2a | Is the attested platform or VM measurement valid under policy? | TDX / SNP / vTPM evidence, CoRIM reference values, platform verifier |
| L2b | Is the attested platform the intended service, tenant, deployment, or environment? | local expected identity policy, CoRIM or evidence identity fields, deployment metadata |
| L3 | Is the accepted subject the intended workload, process, or agent? | workload ID, agent ID, binary or config hash, agent key, routing target |
| L4 | Is the accepted response tied to the intended computation, task, thread, or context? | computation ID, request context, session tracking, application task binding |
| L5 | Is the accepted action tied to the intended authorization or capability? | policy engine, role/capability token, user consent, application authorization |

## Threat-model mapping

- Relay or borrowed-evidence problems usually point to L0/L1.
- Binding-parameter confusion, such as accepting the wrong exporter label or
  context, is an L1 verifier-policy problem.
- Diversion usually points to L2b: the endpoint can be genuine but not the
  intended service, tenant, deployment, or environment.
- Same-machine wrong-agent problems usually point to L3: the platform can be
  intended while the workload, process, or agent differs.
- Task confusion and authorization failures are higher-layer application
  questions, represented here as L4 and L5.

## Current review posture

L0, L1, and L2a are closest to the current aTLS verifier and attestation code.
They can often be checked with implementation regressions and targeted formal
models.

L2b, L3, L4, and L5 need explicit expected values from deployment or application
policy before the verifier can enforce them. They should be tracked as design
obligations unless a concrete implementation path claims to enforce them.

The related note in `docs/atls-identity-policy-inputs.md` lists example identity
inputs for L2b and L3.
