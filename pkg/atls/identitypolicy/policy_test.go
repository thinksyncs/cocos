// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package identitypolicy

import (
	"errors"
	"testing"
)

func TestValidateAcceptsMatchingRequiredLayers(t *testing.T) {
	policy := Policy{
		Require: Requirements{
			L2B: true,
			L3:  true,
			L4:  true,
			L5:  true,
		},
		Expected: Values{
			Service:              "payments",
			Tenant:               "tenant-a",
			Deployment:           "prod",
			Environment:          "us-east",
			Workload:             "settlement",
			Agent:                "agent-a",
			AgentPublicKey:       "agent-key",
			ComputationID:        "cmp-1",
			TaskID:               "task-1",
			ThreadID:             "thread-1",
			DelegationID:         "delegation-1",
			Scopes:               []string{"read:orders"},
			Resources:            []string{"orders"},
			AuthorizationDetails: []string{"settle"},
		},
	}

	observed := Values{
		Service:              "payments",
		Tenant:               "tenant-a",
		Deployment:           "prod",
		Environment:          "us-east",
		Workload:             "settlement",
		Agent:                "agent-a",
		AgentPublicKey:       "agent-key",
		ComputationID:        "cmp-1",
		TaskID:               "task-1",
		ThreadID:             "thread-1",
		DelegationID:         "delegation-1",
		Scopes:               []string{"read:orders", "write:audit"},
		Resources:            []string{"orders", "audit-log"},
		AuthorizationDetails: []string{"settle", "notify"},
	}

	if err := Validate(policy, observed); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateAcceptsSingleExpectedValuePerRequiredLayer(t *testing.T) {
	policy := Policy{
		Require: Requirements{
			L2B: true,
			L3:  true,
			L4:  true,
			L5:  true,
		},
		Expected: Values{
			Service: "payments",
			Agent:   "agent-a",
			TaskID:  "task-1",
			Scopes:  []string{"read:orders"},
		},
	}

	observed := Values{
		Service:     "payments",
		Tenant:      "different-tenant",
		Deployment:  "different-deployment",
		Environment: "different-environment",
		Workload:    "different-workload",
		Agent:       "agent-a",
		TaskID:      "task-1",
		ThreadID:    "different-thread",
		Scopes:      []string{"read:orders", "write:audit"},
	}

	if err := Validate(policy, observed); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateAcceptsObservedSetSupersetWithDuplicatesAndBlanks(t *testing.T) {
	policy := Policy{
		Require: Requirements{L5: true},
		Expected: Values{
			Scopes:               []string{"read:orders", "read:orders"},
			Resources:            []string{"orders"},
			AuthorizationDetails: []string{"settle"},
		},
	}

	observed := Values{
		Scopes:               []string{" ", "read:orders", "read:orders", "write:audit"},
		Resources:            []string{"orders", "audit-log"},
		AuthorizationDetails: []string{"settle", "notify"},
	}

	if err := Validate(policy, observed); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsMissingExpectedValue(t *testing.T) {
	policy := Policy{
		Require: Requirements{L2B: true},
	}

	err := Validate(policy, Values{Service: "payments"})
	if !errors.Is(err, ErrMissingExpected) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingExpected)
	}
}

func TestValidateRejectsMissingObservedValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L3: true},
		Expected: Values{Agent: "agent-a"},
	}

	err := Validate(policy, Values{})
	if !errors.Is(err, ErrMissingObserved) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingObserved)
	}

	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("Validate() error = %T, want *ValidationError", err)
	}
	if validationErr.Layer != LayerL3 || validationErr.Field != "agent" {
		t.Fatalf("Validate() error layer/field = %s/%s", validationErr.Layer, validationErr.Field)
	}
}

func TestValidateRejectsMismatchedObservedValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L4: true},
		Expected: Values{ComputationID: "cmp-1"},
	}

	err := Validate(policy, Values{ComputationID: "cmp-2"})
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMismatch)
	}
}

func TestValidateRejectsMissingScope(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L5: true},
		Expected: Values{Scopes: []string{"read:orders", "write:orders"}},
	}

	err := Validate(policy, Values{Scopes: []string{"read:orders"}})
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMismatch)
	}
}

func TestValidateReportsAllL5Failures(t *testing.T) {
	policy := Policy{
		Require: Requirements{L5: true},
		Expected: Values{
			Scopes:               []string{"read:orders"},
			Resources:            []string{"orders"},
			AuthorizationDetails: []string{"settle"},
		},
	}

	err := Validate(policy, Values{
		Scopes:    []string{" "},
		Resources: []string{"audit-log"},
	})
	if !errors.Is(err, ErrMissingObserved) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingObserved)
	}
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMismatch)
	}

	var validationErrs ValidationErrors
	if !errors.As(err, &validationErrs) {
		t.Fatalf("Validate() error = %T, want ValidationErrors", err)
	}
	if len(validationErrs) != 3 {
		t.Fatalf("Validate() error count = %d, want 3", len(validationErrs))
	}
	if !validationErrs.Has(LayerL5, FieldScopes, ErrMissingObserved) {
		t.Fatalf("Validate() errors do not include L5 scopes missing observed value")
	}
	if !validationErrs.Has(LayerL5, FieldResources, ErrMismatch) {
		t.Fatalf("Validate() errors do not include L5 resources mismatch")
	}
	if !validationErrs.Has(LayerL5, FieldAuthorizationDetails, ErrMissingObserved) {
		t.Fatalf("Validate() errors do not include L5 authorization details missing observed value")
	}
}

func TestValidateReportsAllLayerFailures(t *testing.T) {
	policy := Policy{
		Require: Requirements{
			L2B: true,
			L3:  true,
			L5:  true,
		},
		Expected: Values{
			Service: "payments",
			Tenant:  "tenant-a",
			Agent:   "agent-a",
			Scopes:  []string{"read:orders"},
		},
	}

	err := policy.Validate(Values{
		Service: "billing",
		Scopes:  []string{"write:orders"},
	})
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMismatch)
	}
	if !errors.Is(err, ErrMissingObserved) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingObserved)
	}

	var validationErrs ValidationErrors
	if !errors.As(err, &validationErrs) {
		t.Fatalf("Validate() error = %T, want ValidationErrors", err)
	}
	if len(validationErrs) != 4 {
		t.Fatalf("Validate() error count = %d, want 4", len(validationErrs))
	}
	if !validationErrs.Has(LayerL2B, FieldService, ErrMismatch) {
		t.Fatalf("Validate() errors do not include L2b service mismatch")
	}
	if !validationErrs.Has(LayerL3, FieldAgent, ErrMissingObserved) {
		t.Fatalf("Validate() errors do not include L3 agent missing observed value")
	}
	if !validationErrs.Has(LayerL5, FieldScopes, nil) {
		t.Fatalf("Validate() errors do not include L5 scopes failure")
	}
}

func TestValidateRejectsBlankExpectedSetValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L5: true},
		Expected: Values{Scopes: []string{"read:orders", " "}},
	}

	err := Validate(policy, Values{Scopes: []string{"read:orders"}})
	if !errors.Is(err, ErrMissingExpected) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingExpected)
	}
}

func TestValidateRejectsBlankOnlyExpectedSetValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L5: true},
		Expected: Values{Scopes: []string{" "}},
	}

	err := Validate(policy, Values{})
	if !errors.Is(err, ErrMissingExpected) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingExpected)
	}
	if errors.Is(err, ErrMissingObserved) {
		t.Fatalf("Validate() error = %v, did not want %v", err, ErrMissingObserved)
	}
}

func TestValidateRejectsBlankObservedSetValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L5: true},
		Expected: Values{Scopes: []string{"read:orders"}},
	}

	err := Validate(policy, Values{Scopes: []string{" "}})
	if !errors.Is(err, ErrMissingObserved) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingObserved)
	}
}

func TestValidateRejectsBlankExpectedExactValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L3: true},
		Expected: Values{Agent: " "},
	}

	err := Validate(policy, Values{Agent: "agent-a"})
	if !errors.Is(err, ErrMissingExpected) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingExpected)
	}
}

func TestValidateRejectsBlankObservedExactValue(t *testing.T) {
	policy := Policy{
		Require:  Requirements{L3: true},
		Expected: Values{Agent: "agent-a"},
	}

	err := Validate(policy, Values{Agent: " "})
	if !errors.Is(err, ErrMissingObserved) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingObserved)
	}
}

func TestValidationErrorsHelpersSkipNilEntries(t *testing.T) {
	errs := ValidationErrors{
		nil,
		validationError(LayerL4, FieldTaskID, ErrMismatch),
	}

	if got := errs.Error(); got != "L4 task_id: identitypolicy: value mismatch" {
		t.Fatalf("ValidationErrors.Error() = %q", got)
	}
	if got := len(errs.Unwrap()); got != 1 {
		t.Fatalf("ValidationErrors.Unwrap() length = %d, want 1", got)
	}
	if !errs.Has(LayerL4, FieldTaskID, ErrMismatch) {
		t.Fatalf("ValidationErrors.Has() = false, want true")
	}
	if got := len(errs.ByLayer(LayerL4)); got != 1 {
		t.Fatalf("ValidationErrors.ByLayer() length = %d, want 1", got)
	}
	if got := len(errs.ByField(FieldTaskID)); got != 1 {
		t.Fatalf("ValidationErrors.ByField() length = %d, want 1", got)
	}
}

func TestAppendValidationErrorsWrapsUnexpectedError(t *testing.T) {
	unexpected := errors.New("unexpected")

	errs := appendValidationErrors(nil, unexpected)
	if len(errs) != 1 {
		t.Fatalf("appendValidationErrors() length = %d, want 1", len(errs))
	}
	if !errs.Has(FieldAll, FieldAll, unexpected) {
		t.Fatalf("appendValidationErrors() did not preserve unexpected error")
	}
	if !errors.Is(errs, unexpected) {
		t.Fatalf("appendValidationErrors() aggregate does not unwrap unexpected error")
	}
}

func TestValidateSkipsUnrequiredLayers(t *testing.T) {
	policy := Policy{
		Expected: Values{
			Service: "payments",
			Agent:   "agent-a",
		},
	}

	if err := Validate(policy, Values{}); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}
