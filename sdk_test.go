package sdk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifier_GetIdentity(t *testing.T) {
	var jwks jose.JSONWebKeySet
	// good keyset
	pKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	assert.NoError(t, err)
	jwkPriv := jose.JSONWebKey{Key: pKey, Use: "sig", Algorithm: string(jose.ES256)}
	thumbprint, err := jwkPriv.Thumbprint(crypto.SHA256)
	assert.NoError(t, err)
	jwkPriv.KeyID = base64.URLEncoding.EncodeToString(thumbprint)
	jwkPub := jose.JSONWebKey{Key: pKey.Public(), KeyID: jwkPriv.KeyID, Use: "sig", Algorithm: string(jose.ES256)}
	jwks.Keys = append(jwks.Keys, jwkPub)
	goodSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwkPriv}, nil)
	assert.NoError(t, err)
	// bad signer
	badKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	assert.NoError(t, err)
	badJWK := jose.JSONWebKey{Key: badKey, Use: "sig", Algorithm: string(jose.ES256)}
	badJWK.KeyID = jwkPriv.KeyID
	badSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: badJWK}, nil)
	assert.NoError(t, err)

	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, err := FromContext(r.Context())
		if err != nil {
			fmt.Fprintf(w, `{"error":"%s"}`, err)
			return
		}
		fmt.Fprint(w, a.Email)
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := json.Marshal(jwks)
		assert.NoError(t, err)
		fmt.Fprint(w, string(b))
	}))
	defer ts.Close()

	start := time.Now()
	iat := jwt.NewNumericDate(start)
	fiveMinutesAgo := jwt.NewNumericDate(start.Add(-5 * time.Minute))
	fiveMinutesFromNow := jwt.NewNumericDate(start.Add(5 * time.Minute))

	tests := []struct {
		name        string
		jwkEndpoint string
		datastore   JSONWebKeyStore
		logger      *log.Logger
		httpClient  *http.Client
		expected    *jwt.Expected
		headerKey   string
		signer      jose.Signer
		identity    *Identity
		headerValue string
		wantNewErr  bool
		want        string
	}{
		{"custom datastore", ts.URL, newMockCache(10), nil, nil, nil, defaultAttestationHeader, goodSigner, &Identity{Email: "user@pomerium.com"}, "", false, "user@pomerium.com"},
		{"bad JWKS url", "http://user:abc{DEf1=ghi@example.com", nil, nil, nil, nil, defaultAttestationHeader, nil, nil, "", true, ""},
		{"can't parse empty JWT", "", nil, nil, nil, nil, defaultAttestationHeader, nil, nil, "", false, `{"error":"attestation token not found"}`},
		{"can't parse malformed JWT", "", nil, nil, nil, nil, defaultAttestationHeader, nil, nil, "malformed", false, `{"error":"failed to parse Pomerium JWT assertion: go-jose/go-jose: compact JWS format must have three parts"}`},
		{"bad signing key", ts.URL, nil, nil, nil, nil, defaultAttestationHeader, badSigner, &Identity{Email: "user@pomerium.com"}, "", false, `{"error":"invalid Pomerium JWT assertion signature: go-jose/go-jose: error in cryptographic primitive"}`},
		{"good", ts.URL, nil, nil, nil, nil, defaultAttestationHeader, goodSigner, &Identity{Email: "user@pomerium.com", Claims: jwt.Claims{IssuedAt: iat, Expiry: fiveMinutesFromNow}}, "", false, "user@pomerium.com"},
		{"good inferred verify endpoint", "", nil, nil, nil, nil, defaultAttestationHeader, goodSigner, &Identity{Email: "user@pomerium.com", Claims: jwt.Claims{Issuer: ts.URL}}, "", false, "user@pomerium.com"},
		{"does not pass iss validation", ts.URL, nil, nil, nil, &jwt.Expected{Issuer: "pomerium"}, defaultAttestationHeader, goodSigner, &Identity{Email: "user@pomerium.com"}, "", false, "{\"error\":\"unexpected Pomerium JWT assertion claim: go-jose/go-jose/jwt: validation failed, invalid issuer claim (iss)\"}"},
		{"does pass iss validation", ts.URL, nil, nil, nil, &jwt.Expected{Issuer: ts.URL}, defaultAttestationHeader, goodSigner, &Identity{Email: "user@pomerium.com", Claims: jwt.Claims{Issuer: ts.URL}}, "", false, "user@pomerium.com"},
		{"good enforces sub validation", ts.URL, nil, nil, nil, &jwt.Expected{Subject: "1234"}, defaultAttestationHeader, goodSigner, &Identity{Email: "user@pomerium.com", Claims: jwt.Claims{Subject: "1234"}}, "", false, "user@pomerium.com"},
		{"expired", ts.URL, nil, nil, nil, nil, defaultAttestationHeader, goodSigner, &Identity{Email: "user@pomerium.com", Claims: jwt.Claims{IssuedAt: fiveMinutesAgo, Expiry: fiveMinutesAgo}}, "", false, `{"error":"unexpected Pomerium JWT assertion claim: go-jose/go-jose/jwt: validation failed, token is expired (exp)"}`},
		{"issued in the future", ts.URL, nil, nil, nil, nil, defaultAttestationHeader, goodSigner, &Identity{Email: "user@pomerium.com", Claims: jwt.Claims{IssuedAt: fiveMinutesFromNow, Expiry: fiveMinutesFromNow}}, "", false, `{"error":"unexpected Pomerium JWT assertion claim: go-jose/go-jose/jwt: validation field, token issued in the future (iat)"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := New(&Options{
				JWKSEndpoint: tt.jwkEndpoint,
				Datastore:    tt.datastore,
				Logger:       tt.logger,
				HTTPClient:   tt.httpClient,
				Expected:     tt.expected,
			})

			if (err != nil) != tt.wantNewErr {
				t.Errorf("Verifier.New() error = %v, wantNewErr %v", err, tt.wantNewErr)
				return
			} else if err != nil {
				// expected error
				return
			}

			r := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.signer != nil {
				b, err := json.Marshal(tt.identity)
				assert.NoError(t, err)
				obj, err := tt.signer.Sign(b)
				assert.NoError(t, err)
				serialized := obj.FullSerialize()
				r.Header.Set(tt.headerKey, serialized)
			} else if tt.headerValue != "" {
				r.Header.Set(tt.headerKey, tt.headerValue)
			}

			w := httptest.NewRecorder()
			srv := AddIdentityToRequest(v)(fn)
			srv.ServeHTTP(w, r)
			resp := w.Result()
			body, err := io.ReadAll(resp.Body)
			assert.NoError(t, err)

			assert.Equalf(t, tt.want, string(body), "expected body")
		})
	}
}

func TestVerifier_getVerifyEndpoint(t *testing.T) {
	testCases := []struct {
		issuer string
		expect string
	}{
		{"example.com", "https://example.com/.well-known/pomerium/jwks.json"},
		{"https://example.com", "https://example.com/.well-known/pomerium/jwks.json"},
		{"http://example.com", "http://example.com/.well-known/pomerium/jwks.json"},
		{"example.com:1234", "https://example.com:1234/.well-known/pomerium/jwks.json"},
		{"example.com/some/path", "https://example.com/some/path"},
	}

	for _, testCase := range testCases {
		key := []byte("secret")
		sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
		require.NoError(t, err)

		raw, err := jwt.Signed(sig).Claims(jwt.Claims{
			Subject: "subject",
			Issuer:  testCase.issuer,
		}).CompactSerialize()
		require.NoError(t, err)

		tok, err := jwt.ParseSigned(raw)
		require.NoError(t, err)

		v, err := New(&Options{})
		require.NoError(t, err)

		actual, err := v.getVerifyEndpoint(tok)
		require.NoError(t, err)

		assert.Equal(t, testCase.expect, actual)
	}
}

var _ JSONWebKeyStore = &mockCache{}

type mockCache struct {
	capacity int
	data     map[string]*jose.JSONWebKey
	keyIDs   []string
}

func newMockCache(capacity int) *mockCache {
	return &mockCache{
		capacity: capacity,
		data:     make(map[string]*jose.JSONWebKey),
		keyIDs:   make([]string, capacity),
	}
}

func (c *mockCache) Get(keyID string) (*jose.JSONWebKey, bool) {
	val, ok := c.data[keyID]
	return val, ok
}

func (c *mockCache) Add(keyID string, value *jose.JSONWebKey) {
	slot := len(c.data)
	if len(c.data) == c.capacity {
		slot = rand.Intn(c.capacity)
		delete(c.data, c.keyIDs[slot])
	}
	c.keyIDs[slot] = keyID
	c.data[keyID] = value
}
