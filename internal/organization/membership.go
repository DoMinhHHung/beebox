package organization

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

var (
	ErrMembershipNotFound    = errors.New("organization membership not found")
	ErrMembershipUnavailable = errors.New("organization membership unavailable")
)

// MembershipID is a stable BeeBox-owned opaque storage locator for P3.2. P3.2
// exposes no public membership API, so this raw UUIDv4 representation is not a
// ratified public wire encoding.
type MembershipID string

func (id MembershipID) Valid() bool {
	value := string(id)
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	hexBody := strings.ReplaceAll(value, "-", "")
	if len(hexBody) != 32 {
		return false
	}
	raw, err := hex.DecodeString(hexBody)
	if err != nil || len(raw) != 16 {
		return false
	}
	return raw[6]>>4 == 4 && raw[8]&0xc0 == 0x80 && value == strings.ToLower(value)
}

type Membership struct {
	ID                    MembershipID
	ApplicationInstanceID applicationinstance.InternalID
	OrganizationID        ID
	UserPublicID          identity.PublicID
	CreatedAt             time.Time
}

// ActiveOrganization is request/use-case context derived from current
// PostgreSQL membership. It is not persisted on a user/session and is not JWT
// authority.
type ActiveOrganization struct {
	Organization Organization
	MembershipID MembershipID
	UserPublicID identity.PublicID
}

type MembershipRepository interface {
	CreateMembership(context.Context, MutationContext, ID, identity.PublicID) (Membership, error)
	GetMembership(context.Context, applicationinstance.InternalID, MembershipID) (Membership, error)
	RemoveMembership(context.Context, MutationContext, MembershipID) error
	ResolveActiveOrganization(context.Context, applicationinstance.InternalID, identity.PublicID, ID) (ActiveOrganization, error)
}

type MembershipService struct {
	repository MembershipRepository
}

func NewMembershipService(repository MembershipRepository) (*MembershipService, error) {
	if repository == nil {
		return nil, ErrInvalid
	}
	return &MembershipService{repository: repository}, nil
}

func (s *MembershipService) CreateMembership(ctx context.Context, current MutationContext, organizationID ID, userPublicID identity.PublicID) (Membership, error) {
	if err := ctx.Err(); err != nil {
		return Membership{}, err
	}
	if s == nil || s.repository == nil || !current.Valid() || !organizationID.Valid() || !userPublicID.Valid() {
		return Membership{}, ErrInvalid
	}
	return s.repository.CreateMembership(ctx, current, organizationID, userPublicID)
}

func (s *MembershipService) GetMembership(ctx context.Context, applicationID applicationinstance.InternalID, membershipID MembershipID) (Membership, error) {
	if err := ctx.Err(); err != nil {
		return Membership{}, err
	}
	if s == nil || s.repository == nil || !applicationID.Valid() || !membershipID.Valid() {
		return Membership{}, ErrInvalid
	}
	return s.repository.GetMembership(ctx, applicationID, membershipID)
}

func (s *MembershipService) RemoveMembership(ctx context.Context, current MutationContext, membershipID MembershipID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.repository == nil || !current.Valid() || !membershipID.Valid() {
		return ErrInvalid
	}
	return s.repository.RemoveMembership(ctx, current, membershipID)
}

func (s *MembershipService) ResolveActiveOrganization(ctx context.Context, applicationID applicationinstance.InternalID, userPublicID identity.PublicID, organizationID ID) (ActiveOrganization, error) {
	if err := ctx.Err(); err != nil {
		return ActiveOrganization{}, err
	}
	if s == nil || s.repository == nil || !applicationID.Valid() || !userPublicID.Valid() || !organizationID.Valid() {
		return ActiveOrganization{}, ErrInvalid
	}
	return s.repository.ResolveActiveOrganization(ctx, applicationID, userPublicID, organizationID)
}
