package metricsdelivery

import (
	"context"
	"time"

	beeboxmetrics "github.com/DoMinhHHung/beebox/internal/metrics"
)

type PhoneDelivery interface {
	DeliverPhoneSignupCode(context.Context, string, string, time.Time) error
	DeliverPhoneSignInCode(context.Context, string, string, time.Time) error
}

type PhoneInstrumented struct {
	inner   PhoneDelivery
	metrics *beeboxmetrics.Recorder
}

func NewPhone(inner PhoneDelivery, recorder *beeboxmetrics.Recorder) *PhoneInstrumented {
	return &PhoneInstrumented{inner: inner, metrics: recorder}
}

func (d *PhoneInstrumented) DeliverPhoneSignupCode(ctx context.Context, destination, code string, expiresAt time.Time) error {
	err := d.inner.DeliverPhoneSignupCode(ctx, destination, code, expiresAt)
	d.observe("sms_phone_signup_delivery", err)
	return err
}

func (d *PhoneInstrumented) DeliverPhoneSignInCode(ctx context.Context, destination, code string, expiresAt time.Time) error {
	err := d.inner.DeliverPhoneSignInCode(ctx, destination, code, expiresAt)
	d.observe("sms_phone_signin_delivery", err)
	return err
}

// DeliverPhoneIdentifierVerificationCode intentionally reuses the provider's
// possession-verification SMS transport/message rather than creating a second
// provider protocol. Metrics retain a distinct bounded operation label.
func (d *PhoneInstrumented) DeliverPhoneIdentifierVerificationCode(ctx context.Context, destination, code string, expiresAt time.Time) error {
	err := d.inner.DeliverPhoneSignupCode(ctx, destination, code, expiresAt)
	d.observe("sms_phone_identifier_verification_delivery", err)
	return err
}

func (d *PhoneInstrumented) observe(operation string, err error) {
	if d == nil || d.metrics == nil {
		return
	}
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	d.metrics.Observe(operation, outcome)
}
