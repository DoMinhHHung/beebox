package session

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

const (
	SessionListDefaultLimit = 20
	SessionListMaxLimit     = 100
)

var (
	ErrSessionInvalidRequest = errors.New("invalid session self-service request")
	ErrSessionReverification = errors.New("session self-service reverification required")
)

type SelfServiceRecord struct {
	PublicID      string
	CreatedAt     time.Time
	LastSeenAt    time.Time
	IdleExpiresAt time.Time
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	Current       bool
}

type Cursor struct {
	CreatedAt time.Time `json:"t"`
	PublicID  string    `json:"i"`
}

type Page struct {
	Items      []SelfServiceRecord
	NextCursor string
}

type selfServiceStore interface {
	ListUserSessions(context.Context, applicationinstance.InternalID, identity.InternalID, int, *Cursor) ([]Record, error)
	RevokeUserSession(context.Context, Record, string, audit.CorrelationID) error
	RevokeOtherUserSessions(context.Context, Record, audit.CorrelationID) error
	RevokeAllUserSessions(context.Context, Record, audit.CorrelationID) error
}

func (s *Service) ListSessions(ctx context.Context, appID applicationinstance.InternalID, applicationPublicID, accessToken string, limit int, cursor string) (Page, error) {
	if s == nil {
		return Page{}, ErrSessionUnavailable
	}
	store, ok := s.store.(selfServiceStore)
	if !ok {
		return Page{}, ErrSessionUnavailable
	}
	current, err := s.Current(ctx, appID, applicationPublicID, accessToken)
	if err != nil {
		return Page{}, err
	}
	if limit == 0 {
		limit = SessionListDefaultLimit
	}
	if limit < 1 || limit > SessionListMaxLimit {
		return Page{}, ErrSessionInvalidRequest
	}
	decoded, err := DecodeCursor(cursor)
	if err != nil {
		return Page{}, err
	}
	rows, err := store.ListUserSessions(ctx, current.ApplicationInstanceID, current.UserInternalID, limit+1, decoded)
	if err != nil {
		return Page{}, err
	}
	page := Page{Items: make([]SelfServiceRecord, 0, min(len(rows), limit))}
	for i, row := range rows {
		if i == limit {
			last := rows[limit-1]
			page.NextCursor, err = EncodeCursor(Cursor{CreatedAt: last.CreatedAt.UTC(), PublicID: last.PublicID})
			if err != nil {
				return Page{}, ErrSessionUnavailable
			}
			break
		}
		page.Items = append(page.Items, SelfServiceRecord{
			PublicID:      row.PublicID,
			CreatedAt:     row.CreatedAt.UTC(),
			LastSeenAt:    row.LastSeenAt.UTC(),
			IdleExpiresAt: row.IdleExpiresAt.UTC(),
			ExpiresAt:     row.ExpiresAt.UTC(),
			RevokedAt:     row.RevokedAt,
			Current:       row.PublicID == current.PublicID,
		})
	}
	return page, nil
}

func (s *Service) RevokeOwnSession(ctx context.Context, appID applicationinstance.InternalID, applicationPublicID, accessToken, selectedPublicID string, correlationID audit.CorrelationID) (bool, error) {
	if s == nil {
		return false, ErrSessionInvalidRequest
	}
	store, ok := s.store.(selfServiceStore)
	if !ok || !ValidPublicID(selectedPublicID) || correlationID == (audit.CorrelationID{}) {
		return false, ErrSessionInvalidRequest
	}
	current, err := s.Current(ctx, appID, applicationPublicID, accessToken)
	if err != nil {
		return false, err
	}
	if err := authentication.RequireReverification(ctx, current.ApplicationInstanceID, current.UserInternalID, current.PublicID, authentication.ReverificationPurposeSessionRevoke); err != nil {
		return false, ErrSessionReverification
	}
	if err := store.RevokeUserSession(ctx, current, selectedPublicID, correlationID); err != nil {
		return false, err
	}
	return selectedPublicID == current.PublicID, nil
}

func (s *Service) RevokeOtherSessions(ctx context.Context, appID applicationinstance.InternalID, applicationPublicID, accessToken string, correlationID audit.CorrelationID) error {
	if s == nil {
		return ErrSessionInvalidRequest
	}
	store, ok := s.store.(selfServiceStore)
	if !ok || correlationID == (audit.CorrelationID{}) {
		return ErrSessionInvalidRequest
	}
	current, err := s.Current(ctx, appID, applicationPublicID, accessToken)
	if err != nil {
		return err
	}
	if err := authentication.RequireReverification(ctx, current.ApplicationInstanceID, current.UserInternalID, current.PublicID, authentication.ReverificationPurposeSessionRevokeOthers); err != nil {
		return ErrSessionReverification
	}
	return store.RevokeOtherUserSessions(ctx, current, correlationID)
}

func (s *Service) SignOutEverywhere(ctx context.Context, appID applicationinstance.InternalID, applicationPublicID, accessToken string, correlationID audit.CorrelationID) error {
	if s == nil {
		return ErrSessionInvalidRequest
	}
	store, ok := s.store.(selfServiceStore)
	if !ok || correlationID == (audit.CorrelationID{}) {
		return ErrSessionInvalidRequest
	}
	current, err := s.Current(ctx, appID, applicationPublicID, accessToken)
	if err != nil {
		return err
	}
	if err := authentication.RequireReverification(ctx, current.ApplicationInstanceID, current.UserInternalID, current.PublicID, authentication.ReverificationPurposeSignOutEverywhere); err != nil {
		return ErrSessionReverification
	}
	return store.RevokeAllUserSessions(ctx, current, correlationID)
}

func EncodeCursor(cursor Cursor) (string, error) {
	if cursor.CreatedAt.IsZero() || !ValidPublicID(cursor.PublicID) {
		return "", ErrSessionInvalidRequest
	}
	payload, err := json.Marshal(cursor)
	if err != nil || len(payload) > 256 {
		return "", ErrSessionInvalidRequest
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func DecodeCursor(raw string) (*Cursor, error) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > 512 {
		return nil, ErrSessionInvalidRequest
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(payload) > 256 {
		return nil, ErrSessionInvalidRequest
	}
	var cursor Cursor
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cursor); err != nil || cursor.CreatedAt.IsZero() || !ValidPublicID(cursor.PublicID) {
		return nil, ErrSessionInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrSessionInvalidRequest
	}
	cursor.CreatedAt = cursor.CreatedAt.UTC()
	return &cursor, nil
}
