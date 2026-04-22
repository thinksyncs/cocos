# Verification Workspace

This directory collects the current machine-checking and implementation-level
verification artifacts for the Cocos AI aTLS / attestation flow.

## What is here

- `verification/tamarin`
  protocol-level checks for both the legacy pre-handshake and current
  post-handshake designs, including same-endpoint and same-machine
  intended-agent identity questions
- `verification/proverif`
  relay/diversion analysis aligned with the public discussion around
  `CVE-2026-33697`, plus current-design binding models and two compact legacy
  comparison models
- `pkg/atls/ea/authenticator_test.go`
  implementation-level Go tests for the findings we explored locally

## Recommended reproduction order

1. Run the legacy pre-handshake quick test
2. Run the current implementation-level Go tests
3. Run the Tamarin model
4. Run the ProVerif model

This gives a good progression from legacy design evidence, to current
implementation behavior, to more abstract protocol properties.

## Quick start

### 1. Legacy quick test

```sh
verification/run-legacy-tests.sh
```

Expected highlight:

- `TestFillInAttestationLocal` passes in the legacy worktree at commit `e372cfc`

Notes:

- this targets the old pre-handshake aTLS design
- set `FULL_LEGACY=1` to also run the slower legacy quoteprovider verification tests

### 2. Current Go tests

```sh
verification/run-go-tests.sh
```

What these tests check:

- exporter-label handling:
  `TestDummyAttestationRoundTripAcceptsAlternateExporterLabel`
- missing attestation after an explicit offer:
  `TestValidateAuthenticatorAllowsMissingOfferedAttestation`
- leaf-key substitution resistance:
  `TestValidateAuthenticatorRejectsLeafKeySubstitution`
- session-scoped one-shot vs. replayable API-level context reuse:
  `TestSessionRejectsContextReuse`
  `TestValidateAuthenticatorWithoutSessionAllowsContextReplay`

Expected highlights:

- alternate exporter-label acceptance is reproduced
- missing-attestation-after-offer is reproduced at the API level
- leaf-key substitution is rejected in the narrow current test path
- replay remains possible without session tracking

### 3. Tamarin

```sh
verification/run-tamarin.sh
```

Expected highlights:

- legacy model:
  - `legacy_acceptance_requires_prior_request` is verified
  - `legacy_no_tee_is_fail_closed` is verified
  - `legacy_attestation_binds_nonce_and_public_key` is verified
- `attested_authenticator_has_server_origin` is verified
- `attested_acceptance_requires_prior_offer` is verified
- `plain_requests_do_not_produce_attested_acceptance` is verified
- `accepted_attestation_must_use_default_exporter_label` is falsified
- `offered_requests_must_not_succeed_without_attestation` is falsified
- `received_attestation_has_server_origin` is verified
- `same_endpoint_can_fail_under_leakage` yields a verified attack trace
- `received_machine_attestation_has_machine_origin` is verified
- `intended_agent_identity_can_fail_on_same_machine` yields a verified attack trace
- `received_bound_attestation_has_machine_origin` is verified
- `acceptance_requires_intended_agent_response` is falsified
- `wrong_agent_identity_can_fail_on_same_machine` is falsified with no trace found
- `session_context_is_one_shot` is verified
- `no_session_replay_exists` yields a verified replay trace

### 4. ProVerif

```sh
verification/run-proverif.sh
```

Expected highlights:

- `ClientAccepts ==> ClientSendsEARequest` is `true`
- `ClientAccepts ==> ServerIssuesAttestation` is `true`
- `ClientAccepts ==> ServerBuildsAuthenticator` is `false`
- `ClientAccepts ==> ServerBindsSameChannel` is `false`
- `ClientAccepts ==> ServerUsesCanonicalLabel` is `false`
- `ClientAccepts ==> ServerAttestsLeafKey` is `true`
- `ClientAcceptsLegacy ==> ClientRequestsEvidence` is `true`
- `ClientAcceptsLegacy ==> ServerIssuesLegacyAttestation` is `true`
- `ClientAcceptsLegacy ==> ServerCreatesLegacyReport` is `true`
- `ClientAcceptsLegacy ==> LegacyServerBindsSameChannel` is `false`

## Current interpretation

At the moment, this workspace supports several distinct threads of evidence:

- a legacy pre-handshake aTLS snapshot, with quick reproducibility through an old worktree
- a published relay/diversion-style risk, modeled in ProVerif
- an exporter-label handling issue, seen in Tamarin, Go tests, and ProVerif
- a positive leaf-key substitution check, seen in Go tests and ProVerif
- a weaker attestation-offer handling issue, seen in both Tamarin and Go tests

There is also a narrower usage result around request contexts:

- with `ea.Session`, one-shot context reuse rejection is checked
- without session tracking, replay of the same context remains acceptable at the API level

The ProVerif models are intentionally abstract and should be treated as
design-level evidence, not full proofs of exploitability for the complete
implementation.

## Notes

- The scripts expect `go`, `tamarin-prover`, `opam`, and `proverif` to be
  available in `PATH`.
- If `opam` is not yet initialized in another environment, run:

```sh
opam init --disable-sandboxing -y
```
