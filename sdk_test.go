package sdk

import (
	"context"
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
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

	tests := []struct {
		name        string
		jwkEndpoint string
		datastore   JSONWebKeyStore
		logger      *log.Logger
		httpClient  *http.Client
		expected    *jwt.Expected
		ctx         context.Context
		rawJWT      string
		headerKey   string
		signer      jose.Signer
		identity    *Identity
		headerValue string
		wantNewErr  bool
		want        string
	}{
		{"nil datastore should fail", "", nil, nil, nil, nil, context.TODO(), "", defaultAttestationHeader, nil, nil, "", true, ""},
		{"bad datastore url", "http://user:abc{DEf1=ghi@example.com", new(10), nil, nil, nil, context.TODO(), "", defaultAttestationHeader, nil, nil, "", true, ""},
		{"can't parse empty JWT", "", new(10), nil, nil, nil, context.TODO(), "", defaultAttestationHeader, nil, nil, "", false, `{"error":"attestation token not found"}`},
		{"can't parse malformed JWT", "", new(10), nil, nil, nil, context.TODO(), "", defaultAttestationHeader, nil, nil, "malformed", false, `{"error":"couldn't parse raw JWT: go-jose/go-jose: compact JWS format must have three parts"}`},
		{"bad signing key", ts.URL, new(10), nil, nil, nil, context.TODO(), "", defaultAttestationHeader, badSigner, &Identity{Email: "user@pomerium.com"}, "", false, `{"error":"invalid JWT signature: go-jose/go-jose: error in cryptographic primitive"}`},
		{"good", ts.URL, new(10), nil, nil, nil, context.TODO(), "", defaultAttestationHeader, goodSigner, &Identity{Email: "user@pomerium.com"}, "", false, "user@pomerium.com"},
		{"good inferred verify endpoint", "", new(10), nil, nil, nil, context.TODO(), "", defaultAttestationHeader, goodSigner, &Identity{Email: "user@pomerium.com", Claims: jwt.Claims{Issuer: ts.URL}}, "", false, "user@pomerium.com"},
		{"does not pass iss validation", ts.URL, new(10), nil, nil, &jwt.Expected{Issuer: "pomerium"}, context.TODO(), "", defaultAttestationHeader, goodSigner, &Identity{Email: "user@pomerium.com"}, "", false, "{\"error\":\"unexpected claim: go-jose/go-jose/jwt: validation failed, invalid issuer claim (iss)\"}"},
		{"does pass iss validation", ts.URL, new(10), nil, nil, &jwt.Expected{Issuer: ts.URL}, context.TODO(), "", defaultAttestationHeader, goodSigner, &Identity{Email: "user@pomerium.com", Claims: jwt.Claims{Issuer: ts.URL}}, "", false, "user@pomerium.com"},
		{"good enforces sub validation", ts.URL, new(10), nil, nil, &jwt.Expected{Subject: "1234"}, context.TODO(), "", defaultAttestationHeader, goodSigner, &Identity{Email: "user@pomerium.com", Claims: jwt.Claims{Subject: "1234"}}, "", false, "user@pomerium.com"},
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

		v, err := New(&Options{Datastore: new(10)})
		require.NoError(t, err)

		actual, err := v.getVerifyEndpoint(tok)
		require.NoError(t, err)

		assert.Equal(t, testCase.expect, actual)
	}
}

var _ JSONWebKeyStore = &mockCache{}

type mockCache struct {
	capacity int
	data     map[string]interface{}
	keys     []string
}

func new(capacity int) *mockCache {
	return &mockCache{
		capacity: capacity,
		data:     make(map[string]interface{}),
		keys:     make([]string, capacity),
	}
}

func (c *mockCache) Get(key interface{}) (interface{}, bool) {
	val, ok := c.data[fmt.Sprintf("%s", key)]
	return val, ok
}

func (c *mockCache) Add(key, value interface{}) {
	slot := len(c.data)
	if len(c.data) == c.capacity {
		slot = rand.Intn(c.capacity)
		delete(c.data, c.keys[slot])
	}
	keyString := fmt.Sprintf("%s", key)
	c.keys[slot] = keyString
	c.data[keyString] = value
}
