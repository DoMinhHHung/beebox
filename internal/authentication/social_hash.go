package authentication

import (
	"crypto/sha256"
	"fmt"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
)

func SocialIdentityLockKey(appID applicationinstance.InternalID, provider Provider, subject string) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("social-identity\x00%d\x00%s\x00%s", appID, provider, subject)))
}

func SocialProviderRateLimitKey(provider Provider) [32]byte {
	return sha256.Sum256([]byte("social-provider\x00" + string(provider)))
}
