package authentication

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
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
	AccountIdentifierListDefaultLimit = 20
	AccountIdentifierListMaxLimit     = 100
)

var (
	ErrAccountManagementInvalid        = errors.New("invalid account management request")
	ErrAccountManagementSession        = errors.New("invalid account management session")
	ErrAccountManagementReverification = errors.New("account management reverification required")
	ErrAccountIdentifierUnavailable    = errors.New("identifier unavailable")
	ErrAccountIdentifierNotFound       = errors.New("identifier not found")
	ErrAccountIdentifierUnverified     = errors.New("identifier is not verified")
	ErrAccountManagementPersistence    = errors.New("account management persistence failure")
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
	PublicID   string
	InternalID identity.EmailIdentifierInternalID
	Email      string
	Verified   bool
	Primary    bool
	CreatedAt  time.Time
}

type ManagedPhoneIdentifier struct {
	PublicID   string
	InternalID identity.PhoneIdentifierInternalID
	Phone      string
	Verified   bool
	Primary    bool
	CreatedAt  time.Time
}

type AccountIdentifierCursor struct {
	Kind      string    `json:"k"`
	CreatedAt time.Time `json:"t"`
	PublicID  string    `json:"i"`
}

type ManagedEmailPage struct {
	Items      []ManagedEmailIdentifier
	NextCursor string
}

type ManagedPhonePage struct {
	Items      []ManagedPhoneIdentifier
	NextCursor string
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
	ListManagedEmails(context.Context, applicationinstance.InternalID, identity.InternalID, int, *AccountIdentifierCursor) ([]ManagedEmailIdentifier, error)
	ListManagedPhones(context.Context, applicationinstance.InternalID, identity.InternalID, int, *AccountIdentifierCursor) ([]ManagedPhoneIdentifier, error)
	AddManagedEmail(context.Context, AccountManagementSession, identity.NormalizedEmail, audit.CorrelationID) (ManagedEmailIdentifier, error)
	AddManagedPhone(context.Context, AccountManagementSession, identity.CanonicalPhone, audit.CorrelationID) (ManagedPhoneIdentifier, error)
	ResolveManagedEmail(context.Context, applicationinstance.InternalID, identity.InternalID, string) (ManagedEmailIdentifier, error)
	ResolveManagedPhone(context.Context, applicationinstance.InternalID, identity.InternalID, string) (ManagedPhoneIdentifier, error)
	SetPrimaryManagedEmail(context.Context, AccountManagementSession, string, audit.CorrelationID) error
	SetPrimaryManagedPhone(context.Context, AccountManagementSession, string, audit.CorrelationID) error
	RemoveManagedEmail(context.Context, AccountManagementSession, string, audit.CorrelationID) error
	RemoveManagedPhone(context.Context, AccountManagementSession, string, audit.CorrelationID) error
	IssuePhoneIdentifierVerification(context.Context, AccountManagementSession, identity.PhoneIdentifierInternalID, VerificationCodeHash, audit.CorrelationID) (string, time.Time, error)
	LoadPhoneIdentifierVerification(context.Context, applicationinstance.InternalID, identity.InternalID, identity.PhoneIdentifierInternalID) (PhoneIdentifierVerificationSnapshot, error)
	FinalizePhoneIdentifierVerification(context.Context, AccountManagementSession, identity.PhoneIdentifierInternalID, int64, bool, audit.CorrelationID) (ManagedPhoneIdentifier, error)
	GetAccountProfile(context.Context, applicationinstance.InternalID, identity.InternalID) (AccountProfile, error)
	UpdateAccountProfile(context.Context, AccountManagementSession, AccountProfile, audit.CorrelationID) (AccountProfile, error)
}

type PhoneIdentifierVerificationDelivery interface {
	DeliverPhoneIdentifierVerificationCode(context.Context, string, string, time.Time) error
}

type AccountManagementService struct {
	persistence       AccountManagementPersistence
	limiter           PublicVerificationRateLimiter
	emailVerification *EmailVerificationService
	phoneDelivery     PhoneIdentifierVerificationDelivery
	now               func() time.Time
}

func NewAccountManagementService(p AccountManagementPersistence, emailVerification *EmailVerificationService, phoneDelivery PhoneIdentifierVerificationDelivery) *AccountManagementService {
	limiter, _ := p.(PublicVerificationRateLimiter)
	return &AccountManagementService{
		persistence:       p,
		limiter:           limiter,
		emailVerification: emailVerification,
		phoneDelivery:     phoneDelivery,
		now:               time.Now,
	}
}

func (s *AccountManagementService) ListEmails(ctx context.Context, current AccountManagementSession, limit int, cursor string) (ManagedEmailPage, error) {
	if err := s.validateSession(current); err != nil {
		return ManagedEmailPage{}, err
	}
	limit, decoded, err := accountIdentifierPageInput(limit, cursor, "emails")
	if err != nil {
		return ManagedEmailPage{}, err
	}
	rows, err := s.persistence.ListManagedEmails(ctx, current.ApplicationInstanceID, current.UserID, limit+1, decoded)
	if err != nil {
		return ManagedEmailPage{}, err
	}
	page := ManagedEmailPage{Items: rows}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor, err = EncodeAccountIdentifierCursor(AccountIdentifierCursor{Kind: "emails", CreatedAt: last.CreatedAt.UTC(), PublicID: last.PublicID})
		if err != nil {
			return ManagedEmailPage{}, ErrAccountManagementPersistence
		}
	}
	if page.Items == nil {
		page.Items = []ManagedEmailIdentifier{}
	}
	return page, nil
}

func (s *AccountManagementService) ListPhones(ctx context.Context, current AccountManagementSession, limit int, cursor string) (ManagedPhonePage, error) {
	if err := s.validateSession(current); err != nil {
		return ManagedPhonePage{}, err
	}
	limit, decoded, err := accountIdentifierPageInput(limit, cursor, "phones")
	if err != nil {
		return ManagedPhonePage{}, err
	}
	rows, err := s.persistence.ListManagedPhones(ctx, current.ApplicationInstanceID, current.UserID, limit+1, decoded)
	if err != nil {
		return ManagedPhonePage{}, err
	}
	page := ManagedPhonePage{Items: rows}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor, err = EncodeAccountIdentifierCursor(AccountIdentifierCursor{Kind: "phones", CreatedAt: last.CreatedAt.UTC(), PublicID: last.PublicID})
		if err != nil {
			return ManagedPhonePage{}, ErrAccountManagementPersistence
		}
	}
	if page.Items == nil {
		page.Items = []ManagedPhoneIdentifier{}
	}
	return page, nil
}

func (s *AccountManagementService) AddEmail(ctx context.Context, current AccountManagementSession, raw string, correlationID audit.CorrelationID) (ManagedEmailIdentifier, error) {
	if err := s.requireMutation(ctx, current, ReverificationPurposeIdentifierAdd, correlationID); err != nil {
		return ManagedEmailIdentifier{}, err
	}
	email, err := identity.NormalizeEmail(raw)
	if err != nil {
		return ManagedEmailIdentifier{}, ErrAccountManagementInvalid
	}
	return s.persistence.AddManagedEmail(ctx, current, email, correlationID)
}

func (s *AccountManagementService) AddPhone(ctx context.Context, current AccountManagementSession, raw string, correlationID audit.CorrelationID) (ManagedPhoneIdentifier, error) {
	if err := s.requireMutation(ctx, current, ReverificationPurposeIdentifierAdd, correlationID); err != nil {
		return ManagedPhoneIdentifier{}, err
	}
	phone, err := identity.NormalizePhone(raw)
	if err != nil {
		return ManagedPhoneIdentifier{}, ErrAccountManagementInvalid
	}
	return s.persistence.AddManagedPhone(ctx, current, phone, correlationID)
}

func (s *AccountManagementService) IssueEmailVerification(ctx context.Context, current AccountManagementSession, publicID string, correlationID audit.CorrelationID) error {
	if err := s.validateSession(current); err != nil {
		return err
	}
	if correlationID == (audit.CorrelationID{}) || !publicid.IsUUIDv4(publicID, "eml") || s.emailVerification == nil || s.limiter == nil {
		return ErrAccountIdentifierNotFound
	}
	item, err := s.persistence.ResolveManagedEmail(ctx, current.ApplicationInstanceID, current.UserID, publicID)
	if err != nil {
		return ErrAccountIdentifierNotFound
	}
	if item.Verified {
		return nil
	}
	normalized, err := identity.NormalizeEmail(item.Email)
	if err != nil {
		return ErrAccountManagementPersistence
	}
	fingerprint := sha256.Sum256([]byte("account-email-verification-issue\x00" + normalized.ComparisonKey))
	if err := s.limiter.AllowPublicVerificationIssue(ctx, current.ApplicationInstanceID, fingerprint); err != nil {
		return mapAccountVerificationError(err)
	}
	if err := s.emailVerification.IssueEmailVerificationWithCorrelation(ctx, current.ApplicationInstanceID, item.InternalID, correlationID); err != nil {
		return mapAccountVerificationError(err)
	}
	return nil
}

func (s *AccountManagementService) ConfirmEmailVerification(ctx context.Context, current AccountManagementSession, publicID, code string, correlationID audit.CorrelationID) (ManagedEmailIdentifier, error) {
	if err := s.validateSession(current); err != nil {
		return ManagedEmailIdentifier{}, err
	}
	if correlationID == (audit.CorrelationID{}) || !publicid.IsUUIDv4(publicID, "eml") || s.emailVerification == nil || s.limiter == nil || !validVerificationCode(code) {
		return ManagedEmailIdentifier{}, ErrAccountManagementInvalid
	}
	item, err := s.persistence.ResolveManagedEmail(ctx, current.ApplicationInstanceID, current.UserID, publicID)
	if err != nil {
		return ManagedEmailIdentifier{}, ErrAccountIdentifierNotFound
	}
	if item.Verified {
		return item, nil
	}
	normalized, err := identity.NormalizeEmail(item.Email)
	if err != nil {
		return ManagedEmailIdentifier{}, ErrAccountManagementPersistence
	}
	fingerprint := sha256.Sum256([]byte("account-email-verification-confirm\x00" + normalized.ComparisonKey))
	if err := s.limiter.AllowPublicVerificationConfirm(ctx, current.ApplicationInstanceID, fingerprint); err != nil {
		return ManagedEmailIdentifier{}, mapAccountVerificationError(err)
	}
	if _, err := s.emailVerification.VerifyEmailCodeWithCorrelation(ctx, current.ApplicationInstanceID, item.InternalID, code, correlationID); err != nil {
		return ManagedEmailIdentifier{}, mapAccountVerificationError(err)
	}
	return s.persistence.ResolveManagedEmail(ctx, current.ApplicationInstanceID, current.UserID, publicID)
}

func (s *AccountManagementService) IssuePhoneVerification(ctx context.Context, current AccountManagementSession, publicID string, correlationID audit.CorrelationID) error {
	if err := s.validateSession(current); err != nil {
		return err
	}
	if correlationID == (audit.CorrelationID{}) || !publicid.IsUUIDv4(publicID, "phn") || s.phoneDelivery == nil || s.limiter == nil {
		return ErrAccountIdentifierNotFound
	}
	item, err := s.persistence.ResolveManagedPhone(ctx, current.ApplicationInstanceID, current.UserID, publicID)
	if err != nil {
		return ErrAccountIdentifierNotFound
	}
	if item.Verified {
		return nil
	}
	phone, err := identity.NormalizePhone(item.Phone)
	if err != nil {
		return ErrAccountManagementPersistence
	}
	fingerprint := sha256.Sum256([]byte("account-phone-verification-issue\x00" + phone.E164))
	if err := s.limiter.AllowPublicVerificationIssue(ctx, current.ApplicationInstanceID, fingerprint); err != nil {
		return mapAccountVerificationError(err)
	}
	code, err := GenerateVerificationCode()
	if err != nil {
		return ErrAccountManagementPersistence
	}
	hash, err := HashVerificationCodeContext(ctx, code)
	if err != nil {
		return mapAccountVerificationError(err)
	}
	destination, expiresAt, err := s.persistence.IssuePhoneIdentifierVerification(ctx, current, item.InternalID, hash, correlationID)
	if err != nil {
		return mapAccountVerificationError(err)
	}
	if err := s.phoneDelivery.DeliverPhoneIdentifierVerificationCode(ctx, destination, code, expiresAt); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return ErrPhoneOTPDelivery
	}
	return nil
}

func (s *AccountManagementService) ConfirmPhoneVerification(ctx context.Context, current AccountManagementSession, publicID, code string, correlationID audit.CorrelationID) (ManagedPhoneIdentifier, error) {
	if err := s.validateSession(current); err != nil {
		return ManagedPhoneIdentifier{}, err
	}
	if correlationID == (audit.CorrelationID{}) || !publicid.IsUUIDv4(publicID, "phn") || !validVerificationCode(code) || s.limiter == nil {
		return ManagedPhoneIdentifier{}, ErrAccountManagementInvalid
	}
	item, err := s.persistence.ResolveManagedPhone(ctx, current.ApplicationInstanceID, current.UserID, publicID)
	if err != nil {
		return ManagedPhoneIdentifier{}, ErrAccountIdentifierNotFound
	}
	if item.Verified {
		return item, nil
	}
	phone, err := identity.NormalizePhone(item.Phone)
	if err != nil {
		return ManagedPhoneIdentifier{}, ErrAccountManagementPersistence
	}
	fingerprint := sha256.Sum256([]byte("account-phone-verification-confirm\x00" + phone.E164))
	if err := s.limiter.AllowPublicVerificationConfirm(ctx, current.ApplicationInstanceID, fingerprint); err != nil {
		return ManagedPhoneIdentifier{}, mapAccountVerificationError(err)
	}
	snapshot, err := s.persistence.LoadPhoneIdentifierVerification(ctx, current.ApplicationInstanceID, current.UserID, item.InternalID)
	if err != nil {
		return ManagedPhoneIdentifier{}, mapAccountVerificationError(err)
	}
	matched := true
	if err := VerifyVerificationCodeContext(ctx, snapshot.CodeHash, code); err != nil {
		switch {
		case errors.Is(err, ErrVerificationCodeMismatch):
			matched = false
		case errors.Is(err, ErrKDFAdmissionLimited):
			return ManagedPhoneIdentifier{}, ErrPublicRateLimited
		default:
			return ManagedPhoneIdentifier{}, ErrAccountManagementPersistence
		}
	}
	item, err = s.persistence.FinalizePhoneIdentifierVerification(ctx, current, item.InternalID, snapshot.Generation, matched, correlationID)
	if err != nil {
		return ManagedPhoneIdentifier{}, mapAccountVerificationError(err)
	}
	return item, nil
}

func (s *AccountManagementService) SetPrimaryEmail(ctx context.Context, current AccountManagementSession, publicID string, correlationID audit.CorrelationID) error {
	if err := s.requireMutation(ctx, current, ReverificationPurposeIdentifierPrimary, correlationID); err != nil {
		return err
	}
	if !publicid.IsUUIDv4(publicID, "eml") {
		return ErrAccountIdentifierNotFound
	}
	return s.persistence.SetPrimaryManagedEmail(ctx, current, publicID, correlationID)
}

func (s *AccountManagementService) SetPrimaryPhone(ctx context.Context, current AccountManagementSession, publicID string, correlationID audit.CorrelationID) error {
	if err := s.requireMutation(ctx, current, ReverificationPurposeIdentifierPrimary, correlationID); err != nil {
		return err
	}
	if !publicid.IsUUIDv4(publicID, "phn") {
		return ErrAccountIdentifierNotFound
	}
	return s.persistence.SetPrimaryManagedPhone(ctx, current, publicID, correlationID)
}

func (s *AccountManagementService) RemoveEmail(ctx context.Context, current AccountManagementSession, publicID string, correlationID audit.CorrelationID) error {
	if err := s.requireMutation(ctx, current, ReverificationPurposeIdentifierRemove, correlationID); err != nil {
		return err
	}
	if !publicid.IsUUIDv4(publicID, "eml") {
		return nil
	}
	return s.persistence.RemoveManagedEmail(ctx, current, publicID, correlationID)
}

func (s *AccountManagementService) RemovePhone(ctx context.Context, current AccountManagementSession, publicID string, correlationID audit.CorrelationID) error {
	if err := s.requireMutation(ctx, current, ReverificationPurposeIdentifierRemove, correlationID); err != nil {
		return err
	}
	if !publicid.IsUUIDv4(publicID, "phn") {
		return nil
	}
	return s.persistence.RemoveManagedPhone(ctx, current, publicID, correlationID)
}

func (s *AccountManagementService) GetProfile(ctx context.Context, current AccountManagementSession) (AccountProfile, error) {
	if err := s.validateSession(current); err != nil {
		return AccountProfile{}, err
	}
	return s.persistence.GetAccountProfile(ctx, current.ApplicationInstanceID, current.UserID)
}

func (s *AccountManagementService) PatchProfile(ctx context.Context, current AccountManagementSession, patch ProfilePatch, correlationID audit.CorrelationID) (AccountProfile, error) {
	if err := s.validateSession(current); err != nil {
		return AccountProfile{}, err
	}
	if correlationID == (audit.CorrelationID{}) {
		return AccountProfile{}, ErrAccountManagementInvalid
	}
	currentProfile, err := s.persistence.GetAccountProfile(ctx, current.ApplicationInstanceID, current.UserID)
	if err != nil {
		return AccountProfile{}, err
	}
	result := currentProfile
	if patch.DisplayName.Present {
		result.DisplayName, err = normalizeProfileName(patch.DisplayName.Value)
	}
	if err == nil && patch.GivenName.Present {
		result.GivenName, err = normalizeProfileName(patch.GivenName.Value)
	}
	if err == nil && patch.FamilyName.Present {
		result.FamilyName, err = normalizeProfileName(patch.FamilyName.Value)
	}
	if err == nil && patch.Locale.Present {
		result.Locale, err = normalizeProfileLocale(patch.Locale.Value)
	}
	if err != nil {
		return AccountProfile{}, ErrAccountManagementInvalid
	}
	return s.persistence.UpdateAccountProfile(ctx, current, result, correlationID)
}

func (s *AccountManagementService) validateSession(current AccountManagementSession) error {
	if s == nil || s.persistence == nil || s.now == nil || !current.ApplicationInstanceID.Valid() || !current.UserID.Valid() || current.SessionPublicID == "" {
		return ErrAccountManagementSession
	}
	now := s.now().UTC()
	if current.Revoked || !current.IdleExpiresAt.After(now) || !current.ExpiresAt.After(now) {
		return ErrAccountManagementSession
	}
	return nil
}

func (s *AccountManagementService) requireMutation(ctx context.Context, current AccountManagementSession, purpose string, correlationID audit.CorrelationID) error {
	if err := s.validateSession(current); err != nil {
		return err
	}
	if correlationID == (audit.CorrelationID{}) {
		return ErrAccountManagementInvalid
	}
	if err := RequireReverification(ctx, current.ApplicationInstanceID, current.UserID, current.SessionPublicID, purpose); err != nil {
		return ErrAccountManagementReverification
	}
	return nil
}

func accountIdentifierPageInput(limit int, cursor, kind string) (int, *AccountIdentifierCursor, error) {
	if limit == 0 {
		limit = AccountIdentifierListDefaultLimit
	}
	if limit < 1 || limit > AccountIdentifierListMaxLimit {
		return 0, nil, ErrAccountManagementInvalid
	}
	decoded, err := DecodeAccountIdentifierCursor(cursor, kind)
	if err != nil {
		return 0, nil, err
	}
	return limit, decoded, nil
}

func EncodeAccountIdentifierCursor(cursor AccountIdentifierCursor) (string, error) {
	if !validAccountIdentifierCursor(cursor, cursor.Kind) {
		return "", ErrAccountManagementInvalid
	}
	payload, err := json.Marshal(cursor)
	if err != nil || len(payload) > 256 {
		return "", ErrAccountManagementInvalid
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func DecodeAccountIdentifierCursor(raw, expectedKind string) (*AccountIdentifierCursor, error) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > 512 {
		return nil, ErrAccountManagementInvalid
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(payload) > 256 {
		return nil, ErrAccountManagementInvalid
	}
	var cursor AccountIdentifierCursor
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cursor); err != nil || !validAccountIdentifierCursor(cursor, expectedKind) {
		return nil, ErrAccountManagementInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrAccountManagementInvalid
	}
	cursor.CreatedAt = cursor.CreatedAt.UTC()
	return &cursor, nil
}

func validAccountIdentifierCursor(cursor AccountIdentifierCursor, expectedKind string) bool {
	if cursor.Kind != expectedKind || cursor.CreatedAt.IsZero() {
		return false
	}
	switch expectedKind {
	case "emails":
		return publicid.IsUUIDv4(cursor.PublicID, "eml")
	case "phones":
		return publicid.IsUUIDv4(cursor.PublicID, "phn")
	default:
		return false
	}
}

func normalizeProfileName(value *string) (*string, error) {
	if value == nil {
		return nil, nil
	}
	normalized := norm.NFC.String(*value)
	if !utf8.ValidString(normalized) || utf8.RuneCountInString(normalized) > 100 {
		return nil, ErrAccountManagementInvalid
	}
	return &normalized, nil
}

func normalizeProfileLocale(value *string) (*string, error) {
	if value == nil {
		return nil, nil
	}
	if *value == "" || strings.TrimSpace(*value) != *value {
		return nil, ErrAccountManagementInvalid
	}
	tag, err := language.Parse(*value)
	if err != nil {
		return nil, ErrAccountManagementInvalid
	}
	canonical := tag.String()
	if len(canonical) > 35 {
		return nil, ErrAccountManagementInvalid
	}
	return &canonical, nil
}

func mapAccountVerificationError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrPublicRateLimited),
		errors.Is(err, ErrKDFAdmissionLimited),
		errors.Is(err, ErrEmailVerificationResendCooldown),
		errors.Is(err, ErrEmailVerificationIssueLimit),
		errors.Is(err, ErrPhoneOTPRateLimited):
		return ErrPublicRateLimited
	case errors.Is(err, ErrEmailVerificationMismatch),
		errors.Is(err, ErrEmailVerificationExpired),
		errors.Is(err, ErrEmailVerificationAttemptLimit),
		errors.Is(err, ErrEmailVerificationAlreadyCompleted),
		errors.Is(err, ErrEmailVerificationChallengeNotFound),
		errors.Is(err, ErrInvalidVerificationCode):
		return ErrAccountManagementInvalid
	default:
		return err
	}
}
