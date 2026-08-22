package organization

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
)

func TestNormalizeOrganizationFields(t *testing.T) {
	t.Parallel()
	name, err := NormalizeName("  Acme Research  ")
	if err != nil || name != "Acme Research" {
		t.Fatalf("NormalizeName() = %q, %v", name, err)
	}
	slug, err := NormalizeSlug("  Acme__Research -- Team  ")
	if err != nil || slug != "acme-research-team" {
		t.Fatalf("NormalizeSlug() = %q, %v", slug, err)
	}
	for _, invalid := range []string{"", "   ", "bad/slug", "café", strings.Repeat("a", SlugMaxBytes+1)} {
		if _, err := NormalizeSlug(invalid); !errors.Is(err, ErrInvalid) {
			t.Fatalf("NormalizeSlug(%q) error = %v, want ErrInvalid", invalid, err)
		}
	}
	for _, invalid := range []string{"", "bad\nname", strings.Repeat("a", NameMaxRunes+1)} {
		if _, err := NormalizeName(invalid); !errors.Is(err, ErrInvalid) {
			t.Fatalf("NormalizeName(%q) error = %v, want ErrInvalid", invalid, err)
		}
	}
}

func TestOrganizationIDValidationDoesNotRatifyAPrefixedWireEncoding(t *testing.T) {
	t.Parallel()
	valid := ID("01234567-89ab-4cde-8fab-0123456789ab")
	if !valid.Valid() {
		t.Fatalf("valid UUIDv4 storage locator rejected: %q", valid)
	}
	for _, invalid := range []ID{
		"org_01234567-89ab-4cde-8fab-0123456789ab",
		"01234567-89ab-3cde-8fab-0123456789ab",
		"01234567-89ab-4cde-7fab-0123456789ab",
		"01234567-89AB-4CDE-8FAB-0123456789AB",
	} {
		if invalid.Valid() {
			t.Fatalf("invalid internal organization locator accepted: %q", invalid)
		}
	}
}

func TestListCursorIsOpaqueScopedAndTamperEvident(t *testing.T) {
	t.Parallel()
	appA := applicationinstance.InternalID(11)
	appB := applicationinstance.InternalID(12)
	repository := &cursorTestRepository{items: []Organization{
		{ID: ID("01234567-89ab-4cde-8fab-0123456789ab"), ApplicationInstanceID: appA, CreatedAt: time.Unix(1_800_000_000, 0).UTC()},
		{ID: ID("11234567-89ab-4cde-8fab-0123456789ab"), ApplicationInstanceID: appA, CreatedAt: time.Unix(1_800_000_001, 0).UTC()},
	}}
	var key CursorKey
	for i := range key {
		key[i] = byte(i + 1)
	}
	service, err := NewService(repository, key)
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.List(context.Background(), appA, 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Organizations) != 1 || page.NextCursor == "" {
		t.Fatalf("page = %#v, want one item and opaque cursor", page)
	}
	if strings.Contains(page.NextCursor, string(page.Organizations[0].ID)) {
		t.Fatalf("cursor exposes organization locator: %q", page.NextCursor)
	}
	callsAfterFirstPage := repository.listCalls
	if _, err := service.List(context.Background(), appB, 1, page.NextCursor); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cross-application cursor error = %v, want ErrInvalidCursor", err)
	}
	if repository.listCalls != callsAfterFirstPage {
		t.Fatal("cross-application cursor reached repository")
	}
	tampered := page.NextCursor[:len(page.NextCursor)-1] + differentCursorByte(page.NextCursor[len(page.NextCursor)-1])
	if _, err := service.List(context.Background(), appA, 1, tampered); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("tampered cursor error = %v, want ErrInvalidCursor", err)
	}
	if _, err := service.List(context.Background(), appA, 1, "not-a-cursor"); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("malformed cursor error = %v, want ErrInvalidCursor", err)
	}
}

func differentCursorByte(value byte) string {
	if value == 'A' {
		return "B"
	}
	return "A"
}

type cursorTestRepository struct {
	items     []Organization
	listCalls int
}

func (*cursorTestRepository) Create(context.Context, MutationContext, string, string) (Organization, error) {
	return Organization{}, errors.New("unexpected Create")
}

func (*cursorTestRepository) Get(context.Context, applicationinstance.InternalID, ID) (Organization, error) {
	return Organization{}, errors.New("unexpected Get")
}

func (r *cursorTestRepository) List(_ context.Context, _ applicationinstance.InternalID, limit int, _ *ListPosition) ([]Organization, error) {
	r.listCalls++
	if limit >= len(r.items) {
		return append([]Organization(nil), r.items...), nil
	}
	return append([]Organization(nil), r.items[:limit]...), nil
}

func (*cursorTestRepository) Update(context.Context, MutationContext, ID, string, string) (Organization, error) {
	return Organization{}, errors.New("unexpected Update")
}
