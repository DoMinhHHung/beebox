package organization

import (
	"context"
	"errors"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

func TestMembershipIDValidationDoesNotRatifyAPrefixedWireEncoding(t *testing.T) {
	t.Parallel()
	valid := MembershipID("01234567-89ab-4cde-8fab-0123456789ab")
	if !valid.Valid() {
		t.Fatalf("valid UUIDv4 storage locator rejected: %q", valid)
	}
	for _, invalid := range []MembershipID{
		"mem_01234567-89ab-4cde-8fab-0123456789ab",
		"01234567-89ab-3cde-8fab-0123456789ab",
		"01234567-89ab-4cde-7fab-0123456789ab",
		"01234567-89AB-4CDE-8FAB-0123456789AB",
	} {
		if invalid.Valid() {
			t.Fatalf("invalid internal membership locator accepted: %q", invalid)
		}
	}
}

func TestMembershipServiceRejectsInvalidLocatorsBeforeRepository(t *testing.T) {
	t.Parallel()
	repository := &membershipTestRepository{}
	service, err := NewMembershipService(repository)
	if err != nil {
		t.Fatal(err)
	}
	current := MutationContext{
		ApplicationInstanceID: applicationinstance.InternalID(1),
		ActorUserID:           identity.InternalID(1),
		CorrelationID:         audit.CorrelationID{1},
	}
	validOrganization := ID("01234567-89ab-4cde-8fab-0123456789ab")
	validUser := identity.PublicID("usr_11234567-89ab-4cde-8fab-0123456789ab")
	validMembership := MembershipID("21234567-89ab-4cde-8fab-0123456789ab")

	if _, err := service.CreateMembership(context.Background(), current, ID("bad"), validUser); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid organization CreateMembership() error = %v", err)
	}
	if _, err := service.CreateMembership(context.Background(), current, validOrganization, identity.PublicID("bad")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid user CreateMembership() error = %v", err)
	}
	if _, err := service.GetMembership(context.Background(), 0, validMembership); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid application GetMembership() error = %v", err)
	}
	if err := service.RemoveMembership(context.Background(), current, MembershipID("bad")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid membership RemoveMembership() error = %v", err)
	}
	if _, err := service.ResolveActiveOrganization(context.Background(), current.ApplicationInstanceID, validUser, ID("bad")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid organization ResolveActiveOrganization() error = %v", err)
	}
	if repository.calls != 0 {
		t.Fatalf("invalid locators reached repository %d times", repository.calls)
	}
}

type membershipTestRepository struct {
	calls int
}

func (r *membershipTestRepository) CreateMembership(context.Context, MutationContext, ID, identity.PublicID) (Membership, error) {
	r.calls++
	return Membership{}, nil
}

func (r *membershipTestRepository) GetMembership(context.Context, applicationinstance.InternalID, MembershipID) (Membership, error) {
	r.calls++
	return Membership{}, nil
}

func (r *membershipTestRepository) RemoveMembership(context.Context, MutationContext, MembershipID) error {
	r.calls++
	return nil
}

func (r *membershipTestRepository) ResolveActiveOrganization(context.Context, applicationinstance.InternalID, identity.PublicID, ID) (ActiveOrganization, error) {
	r.calls++
	return ActiveOrganization{}, nil
}
