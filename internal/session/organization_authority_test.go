package session

import (
	"reflect"
	"testing"
)

func TestAccessTokenClaimsDoNotCarryOrganizationAuthority(t *testing.T) {
	t.Parallel()
	typeOfClaims := reflect.TypeOf(Claims{})
	for _, forbidden := range []string{"org", "organization_id", "membership_id", "role", "roles", "permission", "permissions"} {
		for i := 0; i < typeOfClaims.NumField(); i++ {
			field := typeOfClaims.Field(i)
			if field.Tag.Get("json") == forbidden || field.Name == forbidden {
				t.Fatalf("access-token claims unexpectedly contain mutable organization authority %q", forbidden)
			}
		}
	}
}
