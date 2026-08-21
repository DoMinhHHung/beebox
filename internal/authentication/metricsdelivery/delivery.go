package metricsdelivery

import (
	"context"
	"time"

	beeboxmetrics "github.com/DoMinhHHung/beebox/internal/metrics"
)

type Delivery interface {
	DeliverVerificationCode(context.Context, string, string, time.Time) error
	DeliverPasswordResetCode(context.Context, string, string, time.Time) error
	DeliverSignInCode(context.Context, string, string, time.Time) error
	DeliverSignInLink(context.Context, string, string, time.Time) error
}

type Instrumented struct {
	inner   Delivery
	metrics *beeboxmetrics.Recorder
}

func New(inner Delivery, recorder *beeboxmetrics.Recorder) *Instrumented {
	return &Instrumented{inner: inner, metrics: recorder}
}

func (d *Instrumented) DeliverVerificationCode(ctx context.Context, destination, code string, expiresAt time.Time) error {
	err := d.inner.DeliverVerificationCode(ctx, destination, code, expiresAt)
	d.observe(err)
	return err
}

func (d *Instrumented) DeliverPasswordResetCode(ctx context.Context, destination, code string, expiresAt time.Time) error {
	err := d.inner.DeliverPasswordResetCode(ctx, destination, code, expiresAt)
	d.observe(err)
	return err
}

func (d *Instrumented) DeliverSignInCode(ctx context.Context, destination, code string, expiresAt time.Time) error {
	err := d.inner.DeliverSignInCode(ctx, destination, code, expiresAt)
	d.observe(err)
	return err
}

func (d *Instrumented) DeliverSignInLink(ctx context.Context, destination, link string, expiresAt time.Time) error {
	err := d.inner.DeliverSignInLink(ctx, destination, link, expiresAt)
	d.observe(err)
	return err
}

func (d *Instrumented) observe(err error) {
	if d == nil || d.metrics == nil {
		return
	}
	if err == nil {
		d.metrics.Observe("smtp_delivery", "success")
		return
	}
	d.metrics.Observe("smtp_delivery", "failure")
}
