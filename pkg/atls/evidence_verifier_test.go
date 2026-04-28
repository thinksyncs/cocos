// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package atls

import (
	"testing"

	"github.com/google/go-sev-guest/proto/sevsnp"
	eaattestation "github.com/ultravioletrs/cocos/pkg/atls/eaattestation"
	cocosattestation "github.com/ultravioletrs/cocos/pkg/attestation"
	"google.golang.org/protobuf/proto"
)

func testEvidenceBinding() eaattestation.EvidenceBinding {
	var binding eaattestation.EvidenceBinding
	for i := range binding.ReportData {
		binding.ReportData[i] = byte(i + 1)
	}
	for i := range binding.Nonce {
		binding.Nonce[i] = byte(0xa0 + i)
	}
	return binding
}

func TestVerifyEvidenceBindingRejectsTDXReportDataMismatch(t *testing.T) {
	expected := testEvidenceBinding()
	report := make([]byte, 0x248)
	copy(report[0x208:0x248], expected.ReportData[:])

	if err := verifyEvidenceBinding(cocosattestation.TDX, report, expected); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	report[0x208] ^= 0xff
	if err := verifyEvidenceBinding(cocosattestation.TDX, report, expected); err == nil {
		t.Fatal("expected mismatched TDX report data to fail")
	}
}

func TestVerifyEvidenceBindingRejectsSNPReportDataMismatch(t *testing.T) {
	expected := testEvidenceBinding()
	report, err := proto.Marshal(&sevsnp.Attestation{
		Report: &sevsnp.Report{
			ReportData: append([]byte(nil), expected.ReportData[:]...),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := verifyEvidenceBinding(cocosattestation.SNP, report, expected); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var wrong eaattestation.EvidenceBinding
	copy(wrong.ReportData[:], expected.ReportData[:])
	wrong.ReportData[0] ^= 0xff
	if err := verifyEvidenceBinding(cocosattestation.SNP, report, wrong); err == nil {
		t.Fatal("expected mismatched SNP report data to fail")
	}
}
