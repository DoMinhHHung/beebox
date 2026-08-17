package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestGenerateSigningKeyOperatorIsExplicitOneTimeOutput(t *testing.T) {
	var output bytes.Buffer
	if err := runOperator(context.Background(), testLookup(nil), &output, []string{"generate-signing-key"}); err != nil {
		t.Fatalf("runOperator() error = %v", err)
	}
	text := output.String()
	if !strings.Contains(text, "kid=key_") || !strings.Contains(text, "private_key=") || !strings.Contains(text, "public_key=") {
		t.Fatalf("operator output missing expected explicit key material fields")
	}
	if strings.Contains(text, "error") || strings.Contains(text, "slog") {
		t.Fatal("operator output included logging/error text")
	}
}

func TestOperatorCommandRecognitionDoesNotChangeServeOrMigrateParsing(t *testing.T) {
	if isOperatorCommand(nil) || isOperatorCommand([]string{"migrate"}) || isOperatorCommand([]string{"unknown"}) {
		t.Fatal("non-operator command recognized as operator command")
	}
	if !isOperatorCommand([]string{"bootstrap-application"}) || !isOperatorCommand([]string{"generate-signing-key"}) {
		t.Fatal("operator command was not recognized")
	}
}
