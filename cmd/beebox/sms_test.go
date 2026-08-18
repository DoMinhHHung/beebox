package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/authentication/plivodelivery"
	"github.com/DoMinhHHung/beebox/internal/authentication/telnyxdelivery"
	"github.com/DoMinhHHung/beebox/internal/authentication/twiliodelivery"
	"github.com/DoMinhHHung/beebox/internal/authentication/vonagedelivery"
)

func TestBuildSMSDeliveryDefaultsDisabledAndSelectsExactlyOneProvider(t *testing.T) {
	for _, values := range []map[string]string{nil, {"BEEBOX_SMS_MODE": "disabled"}, {"BEEBOX_SMS_MODE": ""}} {
		delivery, enabled, err := buildSMSDelivery(testLookup(values))
		if err != nil || enabled || delivery != nil {
			t.Fatalf("disabled selection = delivery=%T enabled=%v err=%v", delivery, enabled, err)
		}
	}

	for _, tc := range []struct {
		name   string
		values map[string]string
		assert func(any) bool
	}{
		{
			name: "twilio",
			values: map[string]string{
				"BEEBOX_SMS_MODE":              "twilio",
				"BEEBOX_TWILIO_ACCOUNT_SID":    "AC" + strings.Repeat("0", 32),
				"BEEBOX_TWILIO_API_KEY_SID":    "SK" + strings.Repeat("1", 32),
				"BEEBOX_TWILIO_API_KEY_SECRET": "fixture-twilio-secret",
				"BEEBOX_TWILIO_FROM":           "+15551234567",
			},
			assert: func(value any) bool { _, ok := value.(*twiliodelivery.Delivery); return ok },
		},
		{
			name: "vonage",
			values: map[string]string{
				"BEEBOX_SMS_MODE":          "vonage",
				"BEEBOX_VONAGE_API_KEY":    "fixture-key",
				"BEEBOX_VONAGE_API_SECRET": "fixture-secret",
				"BEEBOX_VONAGE_FROM":       "BeeBox",
			},
			assert: func(value any) bool { _, ok := value.(*vonagedelivery.Delivery); return ok },
		},
		{
			name: "plivo",
			values: map[string]string{
				"BEEBOX_SMS_MODE":         "plivo",
				"BEEBOX_PLIVO_AUTH_ID":    "fixture-auth-id",
				"BEEBOX_PLIVO_AUTH_TOKEN": "fixture-secret",
				"BEEBOX_PLIVO_FROM":       "+15551234567",
			},
			assert: func(value any) bool { _, ok := value.(*plivodelivery.Delivery); return ok },
		},
		{
			name: "telnyx",
			values: map[string]string{
				"BEEBOX_SMS_MODE":       "telnyx",
				"BEEBOX_TELNYX_API_KEY": "fixture-secret",
				"BEEBOX_TELNYX_FROM":    "+15551234567",
			},
			assert: func(value any) bool { _, ok := value.(*telnyxdelivery.Delivery); return ok },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			delivery, enabled, err := buildSMSDelivery(testLookup(tc.values))
			if err != nil || !enabled || delivery == nil || !tc.assert(delivery) {
				t.Fatalf("selection = delivery=%T enabled=%v err=%v", delivery, enabled, err)
			}
		})
	}
}

func TestBuildSMSDeliveryRejectsUnknownModeAndPartialProviderConfigSafely(t *testing.T) {
	if _, _, err := buildSMSDelivery(testLookup(map[string]string{"BEEBOX_SMS_MODE": "typo"})); !errors.Is(err, errSMSDeliveryConfig) {
		t.Fatalf("unknown mode error = %v", err)
	}

	for _, tc := range []struct {
		name   string
		secret string
		values map[string]string
	}{
		{name: "twilio", secret: "fixture-twilio-secret", values: map[string]string{
			"BEEBOX_SMS_MODE": "twilio", "BEEBOX_TWILIO_ACCOUNT_SID": "AC" + strings.Repeat("0", 32), "BEEBOX_TWILIO_API_KEY_SID": "SK" + strings.Repeat("1", 32), "BEEBOX_TWILIO_API_KEY_SECRET": "fixture-twilio-secret",
		}},
		{name: "vonage", secret: "fixture-vonage-secret", values: map[string]string{
			"BEEBOX_SMS_MODE": "vonage", "BEEBOX_VONAGE_API_KEY": "fixture-key", "BEEBOX_VONAGE_API_SECRET": "fixture-vonage-secret",
		}},
		{name: "plivo", secret: "fixture-plivo-secret", values: map[string]string{
			"BEEBOX_SMS_MODE": "plivo", "BEEBOX_PLIVO_AUTH_ID": "fixture-auth-id", "BEEBOX_PLIVO_AUTH_TOKEN": "fixture-plivo-secret",
		}},
		{name: "telnyx", secret: "fixture-telnyx-secret", values: map[string]string{
			"BEEBOX_SMS_MODE": "telnyx", "BEEBOX_TELNYX_API_KEY": "fixture-telnyx-secret",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := buildSMSDelivery(testLookup(tc.values))
			if !errors.Is(err, errSMSDeliveryConfig) || strings.Contains(err.Error(), tc.secret) {
				t.Fatalf("partial config error = %q", err)
			}
		})
	}
}
