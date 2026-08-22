package openapi_test

import (
	"os"
	"strings"
	"testing"
)

func TestEveryV1OperationDeclaresGatewayEdgeResponses(t *testing.T) {
	data, err := os.ReadFile("v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	methods := map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true, "options": true, "head": true, "trace": true}
	type operation struct {
		name  string
		block []string
	}
	var operations []operation
	currentPath := ""
	current := operation{}
	flush := func() {
		if current.name != "" {
			operations = append(operations, current)
			current = operation{}
		}
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "  /") && strings.HasSuffix(line, ":") {
			flush()
			currentPath = strings.TrimSuffix(strings.TrimSpace(line), ":")
			continue
		}
		if currentPath != "" && strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "      ") && strings.HasSuffix(line, ":") {
			method := strings.TrimSuffix(strings.TrimSpace(line), ":")
			if methods[method] {
				flush()
				if strings.HasPrefix(currentPath, "/v1/") {
					current = operation{name: method + " " + currentPath}
				}
				continue
			}
		}
		if current.name != "" {
			current.block = append(current.block, line)
		}
		if line == "components:" {
			flush()
			currentPath = ""
		}
	}
	flush()
	if len(operations) < 50 {
		t.Fatalf("found only %d /v1 operations; parser likely missed operations", len(operations))
	}
	required := []string{
		"'413': {$ref: '#/components/responses/RequestTooLarge'}",
		"'502': {$ref: '#/components/responses/UpstreamUnavailable'}",
		"'504': {$ref: '#/components/responses/UpstreamTimeout'}",
	}
	for _, operation := range operations {
		block := strings.Join(operation.block, "\n")
		for _, response := range required {
			if !strings.Contains(block, response) {
				t.Errorf("%s is missing Gateway edge response %s", operation.name, response)
			}
		}
	}
}

func TestGatewayEdgeResponseSchemasPinStableCodes(t *testing.T) {
	data, err := os.ReadFile("v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	spec := string(data)
	for _, required := range []string{
		"RequestTooLarge:\n      description:",
		"UpstreamUnavailable:\n      description:",
		"UpstreamTimeout:\n      description:",
		"const: request_too_large",
		"const: upstream_unavailable",
		"const: upstream_timeout",
		"OUTCOME MAY BE UNKNOWN",
		"reuse the same idempotency key",
		"reconcile authoritative state",
	} {
		if !strings.Contains(spec, required) {
			t.Errorf("OpenAPI Gateway contract is missing %q", required)
		}
	}
}
