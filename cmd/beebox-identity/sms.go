package main

import (
	"errors"

	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/authentication/plivodelivery"
	"github.com/DoMinhHHung/beebox/internal/authentication/telnyxdelivery"
	"github.com/DoMinhHHung/beebox/internal/authentication/twiliodelivery"
	"github.com/DoMinhHHung/beebox/internal/authentication/vonagedelivery"
	"github.com/DoMinhHHung/beebox/internal/platform/config"
)

var errSMSDeliveryConfig = errors.New("load SMS delivery configuration")

func buildSMSDelivery(lookup config.LookupEnv) (authentication.PhoneOTPDelivery, bool, error) {
	mode, ok := lookup("BEEBOX_SMS_MODE")
	if !ok || mode == "" || mode == "disabled" {
		return nil, false, nil
	}

	var (
		delivery authentication.PhoneOTPDelivery
		err      error
	)
	switch mode {
	case "twilio":
		delivery, err = twiliodelivery.FromLookup(twiliodelivery.LookupEnv(lookup))
	case "vonage":
		delivery, err = vonagedelivery.FromLookup(vonagedelivery.LookupEnv(lookup))
	case "plivo":
		delivery, err = plivodelivery.FromLookup(plivodelivery.LookupEnv(lookup))
	case "telnyx":
		delivery, err = telnyxdelivery.FromLookup(telnyxdelivery.LookupEnv(lookup))
	default:
		return nil, false, errSMSDeliveryConfig
	}
	if err != nil || delivery == nil {
		return nil, false, errSMSDeliveryConfig
	}
	return delivery, true, nil
}
