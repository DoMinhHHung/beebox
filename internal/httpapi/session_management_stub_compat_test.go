package httpapi

import (
	"context"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/session"
)

// These stubs predate the additive P2.9 self-service surface. Keep unrelated
// authentication tests focused on their own behavior while satisfying the
// production session-management dependency contract.
func (passkeySessionManagementStub) ListSessions(context.Context, applicationinstance.InternalID, string, string, int, string) (session.Page, error) {
	return session.Page{}, session.ErrSessionUnavailable
}
func (passkeySessionManagementStub) RevokeOwnSession(context.Context, applicationinstance.InternalID, string, string, string, audit.CorrelationID) (bool, error) {
	return false, session.ErrSessionUnavailable
}
func (passkeySessionManagementStub) RevokeOtherSessions(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) error {
	return session.ErrSessionUnavailable
}
func (passkeySessionManagementStub) SignOutEverywhere(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) error {
	return session.ErrSessionUnavailable
}

func (*fakeSocialLinkHTTPSessions) ListSessions(context.Context, applicationinstance.InternalID, string, string, int, string) (session.Page, error) {
	return session.Page{}, session.ErrSessionUnavailable
}
func (*fakeSocialLinkHTTPSessions) RevokeOwnSession(context.Context, applicationinstance.InternalID, string, string, string, audit.CorrelationID) (bool, error) {
	return false, session.ErrSessionUnavailable
}
func (*fakeSocialLinkHTTPSessions) RevokeOtherSessions(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) error {
	return session.ErrSessionUnavailable
}
func (*fakeSocialLinkHTTPSessions) SignOutEverywhere(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) error {
	return session.ErrSessionUnavailable
}
