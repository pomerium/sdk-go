package sdk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

func TestFetchJSONWebKeySet(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	k1, err := ecdsa.GenerateKey(elliptic.P256(), random)
	require.NoError(t, err)
	k2, err := ecdsa.GenerateKey(elliptic.P256(), random)
	require.NoError(t, err)
	k3, err := rsa.GenerateKey(random, 2048)
	require.NoError(t, err)

	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: k1.Public(), Use: "sig", Algorithm: string(jose.ES256)},
			{Key: k2.Public(), Use: "sig", Algorithm: string(jose.ES256)},
			{Key: k3.Public(), Use: "sig", Algorithm: string(jose.RS256)},
		},
	}
	bs, err := EncodeJSONWebKeySetToPEM(jwks)
	assert.NoError(t, err)
	assert.Equal(t,
		"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFdloxa3BKandzVW9jWjZlTnhmajZ6cld4bGU3RApYNUcwUDVNYzR2UklLTkdTWFlsOFpKci93dE9VQlhYUWx1Mk5HYkNRaXh4cUlFTEdKMWlRVjFHVGxRPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCi0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tCk1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRXM3L0daNHRJaUgvZFFXVGNxYzYvTjFiZzVMRDIKRlVjN1lTZmJBb0pLYmUyZy9iY0xUNnE3SGRZMjVZS3FTY0FxM2tyR3hoeHNMTENxb2VBTk1CWEJPQT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQotLS0tLUJFR0lOIFBVQkxJQyBLRVktLS0tLQpNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXRFSGkwMEl2QVRNNXNpTExFT3paCm95NkJTQXlEekxLU3ZrVGxPMjZ0bFdQL0oySkNGSjlSOU1rVkFxK3VPR2dsTGd2dmpNd1BjUzZ6TUlMYUIzNkMKRmV0OUJMTnRqNkFGZ2YybkM2d1ovS0hRSFpWbldFcmU4WmZ4N3dhSFV0QnRsa2E0NVRqcVV6YTE3VnZueDZaNwpyZDBkcnBsN285NHZJR05STkNuWC9SSUQrOUY5Z1hBM1RZeEtrU2dRWnU3eEdrdDRNMHpiMU9EdWtYeWprYVBlCjB3by9tRG1haWMzeFFYV0FsaWFnQnBGcWhiNk5oUUdPYkg5VndLVzVtOHh3Rm43dTU3SkNMMzZUMlVpcE1ob3oKa1hFRnFXVWE0b2lzc1FIYndEeUFOck8rdWdSZHV4cVhGeDJGUXUvRG1QbUlwNHVBU0ZTRFU0ajM5VjNVbnBJbgpjd0lEQVFBQgotLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0K",
		base64.StdEncoding.EncodeToString(bs),
	)
}
