package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTTPWrappersDoNotMintIndependentRequestCorrelation(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "correlation.go" {
			continue
		}
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, filepath.Clean(name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "NewCorrelationID" {
				return true
			}
			ident, ok := selector.X.(*ast.Ident)
			if ok && ident.Name == "audit" {
				position := set.Position(call.Pos())
				t.Errorf("%s:%d independently mints request correlation; use correlationForRequest", name, position.Line)
			}
			return true
		})
	}
}
