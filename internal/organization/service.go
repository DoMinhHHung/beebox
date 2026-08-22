package organization

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
)

const (
	cursorVersion = 1
	cursorPurpose = "beebox-organization-list-v1\x00"
)

// CursorKey protects opaque organization-list positions. It must be independent
// from authentication, signing, provider, database and Gateway correlation keys.
type CursorKey [32]byte

func (k CursorKey) Valid() bool { return k != (CursorKey{}) }

type Repository interface {
	Create(context.Context, MutationContext, string, string) (Organization, error)
	Get(context.Context, applicationinstance.InternalID, ID) (Organization, error)
	List(context.Context, applicationinstance.InternalID, int, *ListPosition) ([]Organization, error)
	Update(context.Context, MutationContext, ID, string, string) (Organization, error)
}

type Service struct {
	repository Repository
	cursorKey  CursorKey
}

func NewService(repository Repository, cursorKey CursorKey) (*Service, error) {
	if repository == nil || !cursorKey.Valid() {
		return nil, ErrInvalid
	}
	return &Service{repository: repository, cursorKey: cursorKey}, nil
}

func (s *Service) Create(ctx context.Context, current MutationContext, name, slug string) (Organization, error) {
	if err := ctx.Err(); err != nil {
		return Organization{}, err
	}
	if s == nil || s.repository == nil || !current.Valid() {
		return Organization{}, ErrInvalid
	}
	normalizedName, err := NormalizeName(name)
	if err != nil {
		return Organization{}, err
	}
	normalizedSlug, err := NormalizeSlug(slug)
	if err != nil {
		return Organization{}, err
	}
	return s.repository.Create(ctx, current, normalizedName, normalizedSlug)
}

func (s *Service) Get(ctx context.Context, applicationID applicationinstance.InternalID, id ID) (Organization, error) {
	if err := ctx.Err(); err != nil {
		return Organization{}, err
	}
	if s == nil || s.repository == nil || !applicationID.Valid() || !id.Valid() {
		return Organization{}, ErrInvalid
	}
	return s.repository.Get(ctx, applicationID, id)
}

func (s *Service) Update(ctx context.Context, current MutationContext, id ID, name, slug string) (Organization, error) {
	if err := ctx.Err(); err != nil {
		return Organization{}, err
	}
	if s == nil || s.repository == nil || !current.Valid() || !id.Valid() {
		return Organization{}, ErrInvalid
	}
	normalizedName, err := NormalizeName(name)
	if err != nil {
		return Organization{}, err
	}
	normalizedSlug, err := NormalizeSlug(slug)
	if err != nil {
		return Organization{}, err
	}
	return s.repository.Update(ctx, current, id, normalizedName, normalizedSlug)
}

func (s *Service) List(ctx context.Context, applicationID applicationinstance.InternalID, limit int, cursor string) (Page, error) {
	if err := ctx.Err(); err != nil {
		return Page{}, err
	}
	if s == nil || s.repository == nil || !applicationID.Valid() {
		return Page{}, ErrInvalid
	}
	if limit == 0 {
		limit = ListDefaultLimit
	}
	if limit < 1 || limit > ListMaxLimit {
		return Page{}, ErrInvalid
	}
	var after *ListPosition
	if cursor != "" {
		position, err := s.decodeCursor(applicationID, cursor)
		if err != nil {
			return Page{}, err
		}
		after = &position
	}
	items, err := s.repository.List(ctx, applicationID, limit+1, after)
	if err != nil {
		return Page{}, err
	}
	if len(items) <= limit {
		return Page{Organizations: items}, nil
	}
	visible := append([]Organization(nil), items[:limit]...)
	last := visible[len(visible)-1]
	next, err := s.encodeCursor(applicationID, ListPosition{CreatedAt: last.CreatedAt, ID: last.ID})
	if err != nil {
		return Page{}, ErrInvalidCursor
	}
	return Page{Organizations: visible, NextCursor: next}, nil
}

type cursorPayload struct {
	Version         int    `json:"v"`
	ApplicationID   int64  `json:"a"`
	CreatedAtMicros int64  `json:"t"`
	ID              string `json:"i"`
}

func (s *Service) encodeCursor(applicationID applicationinstance.InternalID, position ListPosition) (string, error) {
	if s == nil || !s.cursorKey.Valid() || !applicationID.Valid() || !position.ID.Valid() || position.CreatedAt.IsZero() {
		return "", ErrInvalidCursor
	}
	payload, err := json.Marshal(cursorPayload{
		Version:         cursorVersion,
		ApplicationID:   int64(applicationID),
		CreatedAtMicros: position.CreatedAt.UTC().UnixMicro(),
		ID:              string(position.ID),
	})
	if err != nil {
		return "", ErrInvalidCursor
	}
	aead, err := cursorAEAD(s.cursorKey)
	if err != nil {
		return "", ErrInvalidCursor
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrInvalidCursor
	}
	sealed := aead.Seal(nil, nonce, payload, []byte(cursorPurpose))
	token := append(nonce, sealed...)
	return base64.RawURLEncoding.EncodeToString(token), nil
}

func (s *Service) decodeCursor(applicationID applicationinstance.InternalID, token string) (ListPosition, error) {
	if s == nil || !s.cursorKey.Valid() || !applicationID.Valid() || token == "" {
		return ListPosition{}, ErrInvalidCursor
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil {
		return ListPosition{}, ErrInvalidCursor
	}
	aead, err := cursorAEAD(s.cursorKey)
	if err != nil || len(raw) <= aead.NonceSize() {
		return ListPosition{}, ErrInvalidCursor
	}
	nonce, ciphertext := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	payload, err := aead.Open(nil, nonce, ciphertext, []byte(cursorPurpose))
	if err != nil {
		return ListPosition{}, ErrInvalidCursor
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var decoded cursorPayload
	if err := decoder.Decode(&decoded); err != nil {
		return ListPosition{}, ErrInvalidCursor
	}
	if err := ensureCursorEOF(decoder); err != nil {
		return ListPosition{}, ErrInvalidCursor
	}
	id := ID(decoded.ID)
	if decoded.Version != cursorVersion || decoded.ApplicationID != int64(applicationID) || decoded.CreatedAtMicros <= 0 || !id.Valid() {
		return ListPosition{}, ErrInvalidCursor
	}
	createdAt := time.UnixMicro(decoded.CreatedAtMicros).UTC()
	if createdAt.IsZero() {
		return ListPosition{}, ErrInvalidCursor
	}
	return ListPosition{CreatedAt: createdAt, ID: id}, nil
}

func cursorAEAD(key CursorKey) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func ensureCursorEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return ErrInvalidCursor
		}
		return err
	}
	return nil
}
