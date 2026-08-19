package authentication

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

const (
	SocialLinkListDefaultLimit = 20
	SocialLinkListMaxLimit     = 100
)

var (
	ErrSocialAccountInvalidRequest       = errors.New("invalid social account management request")
	ErrSocialAccountInvalidSession       = errors.New("invalid social account management session")
	ErrSocialAccountReverification       = errors.New("social account management reverification required")
	ErrLastAuthenticationMethod          = errors.New("last authentication method")
	ErrSocialAccountPersistence          = errors.New("social account management persistence failure")
)

type SocialAccountSession struct {
	ApplicationInstanceID applicationinstance.InternalID
	ApplicationPublicID   applicationinstance.PublicID
	UserID                identity.InternalID
	SessionPublicID       string
	CreatedAt             time.Time
	IdleExpiresAt         time.Time
	ExpiresAt             time.Time
	Revoked               bool
}

type LinkedSocialAccount struct {
	PublicID  string
	Provider  Provider
	CreatedAt time.Time
}

type SocialAccountCursor struct {
	CreatedAt time.Time `json:"t"`
	PublicID  string    `json:"i"`
}

type SocialAccountPage struct {
	Items      []LinkedSocialAccount
	NextCursor string
}

type SocialMethodAvailability struct {
	EmailOTP bool
	PhoneOTP bool
	Social   SocialProviderRegistry
}

type SocialAccountPersistence interface {
	ListSocialAccounts(context.Context, applicationinstance.InternalID, identity.InternalID, int, *SocialAccountCursor) ([]LinkedSocialAccount, error)
	UnlinkSocialAccount(context.Context, SocialAccountSession, string, SocialMethodAvailability, audit.CorrelationID) error
}

type SocialAccountService struct {
	persistence  SocialAccountPersistence
	availability SocialMethodAvailability
	now          func() time.Time
}

func NewSocialAccountService(p SocialAccountPersistence, availability SocialMethodAvailability) *SocialAccountService {
	return &SocialAccountService{persistence: p, availability: availability, now: time.Now}
}

func (s *SocialAccountService) List(ctx context.Context, current SocialAccountSession, limit int, cursor string) (SocialAccountPage, error) {
	if s == nil || s.persistence == nil || !validSocialAccountSession(current) {
		return SocialAccountPage{}, ErrSocialAccountInvalidSession
	}
	if limit == 0 {
		limit = SocialLinkListDefaultLimit
	}
	if limit < 1 || limit > SocialLinkListMaxLimit {
		return SocialAccountPage{}, ErrSocialAccountInvalidRequest
	}
	decoded, err := DecodeSocialAccountCursor(cursor)
	if err != nil {
		return SocialAccountPage{}, ErrSocialAccountInvalidRequest
	}
	rows, err := s.persistence.ListSocialAccounts(ctx, current.ApplicationInstanceID, current.UserID, limit+1, decoded)
	if err != nil {
		return SocialAccountPage{}, err
	}
	page := SocialAccountPage{Items: rows}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor, err = EncodeSocialAccountCursor(SocialAccountCursor{CreatedAt: last.CreatedAt.UTC(), PublicID: last.PublicID})
		if err != nil {
			return SocialAccountPage{}, ErrSocialAccountPersistence
		}
	}
	if page.Items == nil {
		page.Items = []LinkedSocialAccount{}
	}
	return page, nil
}

func (s *SocialAccountService) Unlink(ctx context.Context, current SocialAccountSession, publicID string, correlationID audit.CorrelationID) error {
	if s == nil || s.persistence == nil || s.now == nil || !validSocialAccountSession(current) || !ValidSocialLinkPublicID(publicID) || correlationID == (audit.CorrelationID{}) {
		return ErrSocialAccountInvalidRequest
	}
	now := s.now().UTC()
	if current.Revoked || !now.Before(current.IdleExpiresAt.UTC()) || !now.Before(current.ExpiresAt.UTC()) {
		return ErrSocialAccountInvalidSession
	}
	if !now.Before(current.CreatedAt.UTC().Add(SocialLinkFreshness)) {
		return ErrSocialAccountReverification
	}
	return s.persistence.UnlinkSocialAccount(ctx, current, publicID, s.availability, correlationID)
}

func validSocialAccountSession(s SocialAccountSession) bool {
	return s.ApplicationInstanceID.Valid() && s.ApplicationPublicID.Valid() && s.UserID.Valid() && s.SessionPublicID != "" && !s.CreatedAt.IsZero() && !s.IdleExpiresAt.IsZero() && !s.ExpiresAt.IsZero()
}

func ValidSocialLinkPublicID(raw string) bool {
	if len(raw) != 40 || !strings.HasPrefix(raw, "sli_") {
		return false
	}
	uuid := raw[4:]
	if len(uuid) != 36 || uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-' || uuid[14] != '4' || !strings.Contains("89ab", string(uuid[19])) {
		return false
	}
	for i, ch := range uuid {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !strings.ContainsRune("0123456789abcdef", ch) {
			return false
		}
	}
	return true
}

func EncodeSocialAccountCursor(cursor SocialAccountCursor) (string, error) {
	if cursor.CreatedAt.IsZero() || !ValidSocialLinkPublicID(cursor.PublicID) {
		return "", ErrSocialAccountInvalidRequest
	}
	payload, err := json.Marshal(cursor)
	if err != nil || len(payload) > 256 {
		return "", ErrSocialAccountInvalidRequest
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func DecodeSocialAccountCursor(raw string) (*SocialAccountCursor, error) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > 512 {
		return nil, ErrSocialAccountInvalidRequest
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(payload) > 256 {
		return nil, ErrSocialAccountInvalidRequest
	}
	var cursor SocialAccountCursor
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cursor); err != nil || cursor.CreatedAt.IsZero() || !ValidSocialLinkPublicID(cursor.PublicID) {
		return nil, ErrSocialAccountInvalidRequest
	}
	return &cursor, nil
}
