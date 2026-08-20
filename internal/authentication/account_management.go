package authentication

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/platform/publicid"
	"golang.org/x/text/language"
	"golang.org/x/text/unicode/norm"
)

const (
	AccountIdentifierListLimit = 100
)

var (
	ErrAccountManagementInvalid       = errors.New("invalid account management request")
	ErrAccountManagementSession       = errors.New("invalid account management session")
	ErrAccountManagementReverification = errors.New("account management reverification required")
	ErrAccountIdentifierUnavailable   = errors.New("identifier unavailable")
	ErrAccountIdentifierNotFound      = errors.New("identifier not found")
	ErrAccountIdentifierUnverified    = errors.New("identifier is not verified")
	ErrAccountManagementPersistence   = errors.New("account management persistence failure")
)

type AccountManagementSession struct {
	ApplicationInstanceID applicationinstance.InternalID
	UserID                identity.InternalID
	SessionPublicID       string
	IdleExpiresAt         time.Time
	ExpiresAt             time.Time
	Revoked               bool
}

type ManagedEmailIdentifier struct {
	PublicID  string
	InternalID identity.EmailIdentifierInternalID
	Email     string
	Verified  bool
	Primary   bool
	CreatedAt time.Time
}

type ManagedPhoneIdentifier struct {
	PublicID   string
	InternalID identity.PhoneIdentifierInternalID
	Phone      string
	Verified   bool
	Primary    bool
	CreatedAt  time.Time
}

type AccountProfile struct {
	DisplayName *string
	GivenName   *string
	FamilyName  *string
	Locale      *string
}

type OptionalStringPatch struct {
	Present bool
	Value   *string
}

type ProfilePatch struct {
	DisplayName OptionalStringPatch
	GivenName   OptionalStringPatch
	FamilyName  OptionalStringPatch
	Locale      OptionalStringPatch
}

type PhoneIdentifierVerificationSnapshot struct {
	Generation     int64
	CodeHash       VerificationCodeHash
	ExpiresAt      time.Time
	FailedAttempts int
}

type AccountManagementPersistence interface {
	ListManagedEmails(context.Context, applicationinstance.InternalID, identity.InternalID, int) ([]ManagedEmailIdentifier, error)
	ListManagedPhones(context.Context, applicationinstance.InternalID, identity.InternalID, int) ([]ManagedPhoneIdentifier, error)
	AddManagedEmail(context.Context, AccountManagementSession, identity.Email, audit.CorrelationID) (ManagedEmailIdentifier, error)
	AddManagedPhone(context.Context, AccountManagementSession, identity.Phone, audit.CorrelationID) (ManagedPhoneIdentifier, error)
	ResolveManagedEmail(context.Context, applicationinstance.InternalID, identity.InternalID, string) (ManagedEmailIdentifier, error)
	ResolveManagedPhone(context.Context, applicationinstance.InternalID, identity.InternalID, string) (ManagedPhoneIdentifier, error)
	SetPrimaryManagedEmail(context.Context, AccountManagementSession, string, audit.CorrelationID) error
	SetPrimaryManagedPhone(context.Context, AccountManagementSession, string, audit.CorrelationID) error
	RemoveManagedEmail(context.Context, AccountManagementSession, string, audit.CorrelationID) error
	RemoveManagedPhone(context.Context, AccountManagementSession, string, audit.CorrelationID) error
	IssuePhoneIdentifierVerification(context.Context, applicationinstance.InternalID, identity.PhoneIdentifierInternalID, VerificationCodeHash, audit.CorrelationID) (string, time.Time, error)
	LoadPhoneIdentifierVerification(context.Context, applicationinstance.InternalID, identity.PhoneIdentifierInternalID) (PhoneIdentifierVerificationSnapshot, error)
	FinalizePhoneIdentifierVerification(context.Context, applicationinstance.InternalID, identity.InternalID, identity.PhoneIdentifierInternalID, int64, bool, audit.CorrelationID) (ManagedPhoneIdentifier, error)
	GetAccountProfile(context.Context, applicationinstance.InternalID, identity.InternalID) (AccountProfile, error)
	UpdateAccountProfile(context.Context, AccountManagementSession, AccountProfile, audit.CorrelationID) (AccountProfile, error)
}

type PhoneIdentifierVerificationDelivery interface {
	DeliverPhoneIdentifierVerificationCode(context.Context, string, string, time.Time) error
}

type AccountManagementService struct {
	persistence      AccountManagementPersistence
	emailVerification *EmailVerificationService
	phoneDelivery    PhoneIdentifierVerificationDelivery
	now              func() time.Time
}

func NewAccountManagementService(p AccountManagementPersistence, emailVerification *EmailVerificationService, phoneDelivery PhoneIdentifierVerificationDelivery) *AccountManagementService {
	return &AccountManagementService{persistence: p, emailVerification: emailVerification, phoneDelivery: phoneDelivery, now: time.Now}
}

func (s *AccountManagementService) ListEmails(ctx context.Context, current AccountManagementSession) ([]ManagedEmailIdentifier, error) {
	if err := s.validateSession(current); err != nil { return nil, err }
	return s.persistence.ListManagedEmails(ctx, current.ApplicationInstanceID, current.UserID, AccountIdentifierListLimit)
}

func (s *AccountManagementService) ListPhones(ctx context.Context, current AccountManagementSession) ([]ManagedPhoneIdentifier, error) {
	if err := s.validateSession(current); err != nil { return nil, err }
	return s.persistence.ListManagedPhones(ctx, current.ApplicationInstanceID, current.UserID, AccountIdentifierListLimit)
}

func (s *AccountManagementService) AddEmail(ctx context.Context, current AccountManagementSession, raw string, correlationID audit.CorrelationID) (ManagedEmailIdentifier, error) {
	if err := s.requireMutation(ctx, current, ReverificationPurposeIdentifierAdd, correlationID); err != nil { return ManagedEmailIdentifier{}, err }
	email, err := identity.NormalizeEmail(raw)
	if err != nil { return ManagedEmailIdentifier{}, ErrAccountManagementInvalid }
	return s.persistence.AddManagedEmail(ctx, current, email, correlationID)
}

func (s *AccountManagementService) AddPhone(ctx context.Context, current AccountManagementSession, raw string, correlationID audit.CorrelationID) (ManagedPhoneIdentifier, error) {
	if err := s.requireMutation(ctx, current, ReverificationPurposeIdentifierAdd, correlationID); err != nil { return ManagedPhoneIdentifier{}, err }
	phone, err := identity.NormalizePhone(raw)
	if err != nil { return ManagedPhoneIdentifier{}, ErrAccountManagementInvalid }
	return s.persistence.AddManagedPhone(ctx, current, phone, correlationID)
}

func (s *AccountManagementService) IssueEmailVerification(ctx context.Context, current AccountManagementSession, publicID string) error {
	if err := s.validateSession(current); err != nil { return err }
	if !publicid.IsUUIDv4(publicID, "eml") || s.emailVerification == nil { return ErrAccountIdentifierNotFound }
	item, err := s.persistence.ResolveManagedEmail(ctx, current.ApplicationInstanceID, current.UserID, publicID)
	if err != nil { return ErrAccountIdentifierNotFound }
	if item.Verified { return nil }
	if err := s.emailVerification.IssueEmailVerification(ctx, current.ApplicationInstanceID, item.InternalID); err != nil { return mapAccountVerificationError(err) }
	return nil
}

func (s *AccountManagementService) ConfirmEmailVerification(ctx context.Context, current AccountManagementSession, publicID, code string) (ManagedEmailIdentifier, error) {
	if err := s.validateSession(current); err != nil { return ManagedEmailIdentifier{}, err }
	if !publicid.IsUUIDv4(publicID, "eml") || s.emailVerification == nil { return ManagedEmailIdentifier{}, ErrAccountIdentifierNotFound }
	item, err := s.persistence.ResolveManagedEmail(ctx, current.ApplicationInstanceID, current.UserID, publicID)
	if err != nil { return ManagedEmailIdentifier{}, ErrAccountIdentifierNotFound }
	if item.Verified { return item, nil }
	if _, err := s.emailVerification.VerifyEmailCode(ctx, current.ApplicationInstanceID, item.InternalID, code); err != nil { return ManagedEmailIdentifier{}, mapAccountVerificationError(err) }
	return s.persistence.ResolveManagedEmail(ctx, current.ApplicationInstanceID, current.UserID, publicID)
}

func (s *AccountManagementService) IssuePhoneVerification(ctx context.Context, current AccountManagementSession, publicID string, correlationID audit.CorrelationID) error {
	if err := s.validateSession(current); err != nil { return err }
	if correlationID == (audit.CorrelationID{}) || !publicid.IsUUIDv4(publicID, "phn") || s.phoneDelivery == nil { return ErrAccountIdentifierNotFound }
	item, err := s.persistence.ResolveManagedPhone(ctx, current.ApplicationInstanceID, current.UserID, publicID)
	if err != nil { return ErrAccountIdentifierNotFound }
	if item.Verified { return nil }
	code, err := GenerateVerificationCode()
	if err != nil { return ErrAccountManagementPersistence }
	hash, err := HashVerificationCodeContext(ctx, code)
	if err != nil { return ErrAccountManagementPersistence }
	destination, expiresAt, err := s.persistence.IssuePhoneIdentifierVerification(ctx, current.ApplicationInstanceID, item.InternalID, hash, correlationID)
	if err != nil { return mapAccountVerificationError(err) }
	if err := s.phoneDelivery.DeliverPhoneIdentifierVerificationCode(ctx, destination, code, expiresAt); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil { return ctxErr }
		return ErrPhoneOTPDelivery
	}
	return nil
}

func (s *AccountManagementService) ConfirmPhoneVerification(ctx context.Context, current AccountManagementSession, publicID, code string, correlationID audit.CorrelationID) (ManagedPhoneIdentifier, error) {
	if err := s.validateSession(current); err != nil { return ManagedPhoneIdentifier{}, err }
	if correlationID == (audit.CorrelationID{}) || !publicid.IsUUIDv4(publicID, "phn") || !validVerificationCode(code) { return ManagedPhoneIdentifier{}, ErrAccountManagementInvalid }
	item, err := s.persistence.ResolveManagedPhone(ctx, current.ApplicationInstanceID, current.UserID, publicID)
	if err != nil { return ManagedPhoneIdentifier{}, ErrAccountIdentifierNotFound }
	if item.Verified { return item, nil }
	snapshot, err := s.persistence.LoadPhoneIdentifierVerification(ctx, current.ApplicationInstanceID, item.InternalID)
	if err != nil { return ManagedPhoneIdentifier{}, mapAccountVerificationError(err) }
	matched := true
	if err := VerifyVerificationCode(snapshot.CodeHash, code); err != nil {
		if errors.Is(err, ErrVerificationCodeMismatch) { matched = false } else { return ManagedPhoneIdentifier{}, ErrAccountManagementPersistence }
	}
	return s.persistence.FinalizePhoneIdentifierVerification(ctx, current.ApplicationInstanceID, current.UserID, item.InternalID, snapshot.Generation, matched, correlationID)
}

func (s *AccountManagementService) SetPrimaryEmail(ctx context.Context, current AccountManagementSession, publicID string, correlationID audit.CorrelationID) error {
	if err := s.requireMutation(ctx, current, ReverificationPurposeIdentifierPrimary, correlationID); err != nil { return err }
	if !publicid.IsUUIDv4(publicID, "eml") { return ErrAccountIdentifierNotFound }
	return s.persistence.SetPrimaryManagedEmail(ctx, current, publicID, correlationID)
}

func (s *AccountManagementService) SetPrimaryPhone(ctx context.Context, current AccountManagementSession, publicID string, correlationID audit.CorrelationID) error {
	if err := s.requireMutation(ctx, current, ReverificationPurposeIdentifierPrimary, correlationID); err != nil { return err }
	if !publicid.IsUUIDv4(publicID, "phn") { return ErrAccountIdentifierNotFound }
	return s.persistence.SetPrimaryManagedPhone(ctx, current, publicID, correlationID)
}

func (s *AccountManagementService) RemoveEmail(ctx context.Context, current AccountManagementSession, publicID string, correlationID audit.CorrelationID) error {
	if err := s.requireMutation(ctx, current, ReverificationPurposeIdentifierRemove, correlationID); err != nil { return err }
	if !publicid.IsUUIDv4(publicID, "eml") { return nil }
	return s.persistence.RemoveManagedEmail(ctx, current, publicID, correlationID)
}

func (s *AccountManagementService) RemovePhone(ctx context.Context, current AccountManagementSession, publicID string, correlationID audit.CorrelationID) error {
	if err := s.requireMutation(ctx, current, ReverificationPurposeIdentifierRemove, correlationID); err != nil { return err }
	if !publicid.IsUUIDv4(publicID, "phn") { return nil }
	return s.persistence.RemoveManagedPhone(ctx, current, publicID, correlationID)
}

func (s *AccountManagementService) GetProfile(ctx context.Context, current AccountManagementSession) (AccountProfile, error) {
	if err := s.validateSession(current); err != nil { return AccountProfile{}, err }
	return s.persistence.GetAccountProfile(ctx, current.ApplicationInstanceID, current.UserID)
}

func (s *AccountManagementService) PatchProfile(ctx context.Context, current AccountManagementSession, patch ProfilePatch, correlationID audit.CorrelationID) (AccountProfile, error) {
	if err := s.validateSession(current); err != nil { return AccountProfile{}, err }
	if correlationID == (audit.CorrelationID{}) { return AccountProfile{}, ErrAccountManagementInvalid }
	currentProfile, err := s.persistence.GetAccountProfile(ctx, current.ApplicationInstanceID, current.UserID)
	if err != nil { return AccountProfile{}, err }
	result := currentProfile
	if patch.DisplayName.Present { result.DisplayName, err = normalizeProfileName(patch.DisplayName.Value) }
	if err == nil && patch.GivenName.Present { result.GivenName, err = normalizeProfileName(patch.GivenName.Value) }
	if err == nil && patch.FamilyName.Present { result.FamilyName, err = normalizeProfileName(patch.FamilyName.Value) }
	if err == nil && patch.Locale.Present { result.Locale, err = normalizeProfileLocale(patch.Locale.Value) }
	if err != nil { return AccountProfile{}, ErrAccountManagementInvalid }
	return s.persistence.UpdateAccountProfile(ctx, current, result, correlationID)
}

func (s *AccountManagementService) validateSession(current AccountManagementSession) error {
	if s == nil || s.persistence == nil || s.now == nil || !current.ApplicationInstanceID.Valid() || !current.UserID.Valid() || current.SessionPublicID == "" { return ErrAccountManagementSession }
	now := s.now().UTC()
	if current.Revoked || !current.IdleExpiresAt.After(now) || !current.ExpiresAt.After(now) { return ErrAccountManagementSession }
	return nil
}

func (s *AccountManagementService) requireMutation(ctx context.Context, current AccountManagementSession, purpose string, correlationID audit.CorrelationID) error {
	if err := s.validateSession(current); err != nil { return err }
	if correlationID == (audit.CorrelationID{}) { return ErrAccountManagementInvalid }
	if err := RequireReverification(ctx, current.ApplicationInstanceID, current.UserID, current.SessionPublicID, purpose); err != nil { return ErrAccountManagementReverification }
	return nil
}

func normalizeProfileName(value *string) (*string, error) {
	if value == nil { return nil, nil }
	normalized := norm.NFC.String(*value)
	if !utf8.ValidString(normalized) || utf8.RuneCountInString(normalized) > 100 { return nil, ErrAccountManagementInvalid }
	return &normalized, nil
}

func normalizeProfileLocale(value *string) (*string, error) {
	if value == nil { return nil, nil }
	if *value == "" || strings.TrimSpace(*value) != *value { return nil, ErrAccountManagementInvalid }
	tag, err := language.Parse(*value)
	if err != nil { return nil, ErrAccountManagementInvalid }
	canonical := tag.String()
	if len(canonical) > 35 { return nil, ErrAccountManagementInvalid }
	return &canonical, nil
}

func mapAccountVerificationError(err error) error {
	if err == nil { return nil }
	switch {
	case errors.Is(err, ErrEmailVerificationResendCooldown), errors.Is(err, ErrEmailVerificationIssueLimit), errors.Is(err, ErrPhoneOTPRateLimited):
		return ErrPublicRateLimited
	case errors.Is(err, ErrEmailVerificationMismatch), errors.Is(err, ErrEmailVerificationExpired), errors.Is(err, ErrEmailVerificationAttemptLimit), errors.Is(err, ErrEmailVerificationAlreadyCompleted), errors.Is(err, ErrEmailVerificationChallengeNotFound), errors.Is(err, ErrInvalidVerificationCode):
		return ErrAccountManagementInvalid
	default:
		return err
	}
}
