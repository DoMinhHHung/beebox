package authentication

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

type registrationPersistenceStub struct {
	write RegistrationWrite
	err   error
}

func (s *registrationPersistenceStub) PersistRegistration(_ context.Context, write RegistrationWrite) (RegistrationResult, error) {
	s.write = write
	if s.err != nil {
		return RegistrationResult{}, s.err
	}
	return RegistrationResult{
		User: identity.User{InternalID: 1, ApplicationInstanceID: write.ApplicationInstanceID},
		EmailIdentifier: identity.EmailIdentifier{
			InternalID:            1,
			ApplicationInstanceID: write.ApplicationInstanceID,
			UserID:                1,
			EmailAddress:          write.Email.EmailAddress,
			NormalizedEmail:       write.Email.ComparisonKey,
		},
	}, nil
}

func TestRegistrarValidatesAndNormalizesBeforePersistence(t *testing.T) {
	stub := &registrationPersistenceStub{}
	registrar := NewRegistrar(stub)

	if _, err := registrar.RegisterEmailPassword(context.Background(), 0, "Alice@example.test", []byte("password")); !errors.Is(err, ErrInvalidApplicationInstanceScope) {
		t.Fatalf("invalid app error = %v", err)
	}
	if _, err := registrar.RegisterEmailPassword(context.Background(), 1, "not-an-email", []byte("password")); !errors.Is(err, identity.ErrInvalidEmail) {
		t.Fatalf("invalid email error = %v", err)
	}
	if _, err := registrar.RegisterEmailPassword(context.Background(), 1, "alice@example.test", nil); !errors.Is(err, ErrInvalidPasswordInput) {
		t.Fatalf("invalid password error = %v", err)
	}

	result, err := registrar.RegisterEmailPassword(context.Background(), applicationinstance.InternalID(9), "  Alice@Example.TEST  ", []byte(" synthetic password "))
	if err != nil {
		t.Fatalf("RegisterEmailPassword() error = %v", err)
	}
	if stub.write.Email.EmailAddress != "Alice@Example.TEST" || stub.write.Email.ComparisonKey != "alice@example.test" {
		t.Fatalf("normalized email = %#v", stub.write.Email)
	}
	if !stub.write.PasswordHash.Valid() {
		t.Fatal("registration did not pass a valid existing password hash")
	}
	if result.EmailIdentifier.VerifiedAt != nil {
		t.Fatal("registration result email unexpectedly verified")
	}

	resultType := reflect.TypeOf(RegistrationResult{})
	if _, ok := resultType.FieldByName("PasswordHash"); ok {
		t.Fatal("RegistrationResult must not expose PasswordHash")
	}
}

func TestRegistrarPreservesContextAndPersistenceErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stub := &registrationPersistenceStub{}
	_, err := NewRegistrar(stub).RegisterEmailPassword(ctx, 1, "alice@example.test", []byte("password"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled registration error = %v", err)
	}

	stub = &registrationPersistenceStub{err: ErrRegistrationConflict}
	_, err = NewRegistrar(stub).RegisterEmailPassword(context.Background(), 1, "alice@example.test", []byte("password"))
	if !errors.Is(err, ErrRegistrationConflict) {
		t.Fatalf("persistence conflict error = %v", err)
	}
}
