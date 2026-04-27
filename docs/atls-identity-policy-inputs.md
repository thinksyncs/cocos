# aTLS Identity Policy Inputs

This note tracks identity inputs that are outside the basic TLS channel-binding
mechanism. It is a design note, not a production bug claim.

The current aTLS implementation can be reviewed in layers:

- L1: attestation or authenticator material is bound to the accepted TLS
  session.
- L2a: the attested platform or VM measurement is appraised.
- L2b: the attested platform is checked against the intended service, tenant,
  deployment, or environment.
- L3: the accepted platform is checked against the intended workload, process,
  or agent.

L1 and L2a can be tested directly with implementation regressions. L2b and L3
need explicit policy inputs before the verifier can enforce them consistently.

## L2b: intended service, tenant, or deployment

The verifier needs a local source of expected identity values. Examples include:

- service identity,
- tenant identity,
- deployment or environment identity,
- region or location, if relevant,
- CoRIM or evidence fields that represent these values,
- and the local policy source for the expected values.

The key question is whether a valid platform measurement is also tied to the
intended service or deployment subject.

## L3: intended workload, process, or agent

Machine-level attestation may not be enough when several workloads or agents run
on the same platform. The verifier or application layer may need expected values
such as:

- workload ID,
- agent ID,
- process or binary hash,
- config or policy hash,
- agent public key,
- and routing target or ingress identity.

The key question is whether the accepted peer is the intended workload or agent,
not only a workload on a valid attested machine.

## Suggested next step

Document the expected L2b and L3 identity fields first. After that, add minimal
fail-closed regression tests for missing or mismatched expected identities.
