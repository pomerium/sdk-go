package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

var (
	ErrDatastoreRequired = errors.New("must set a datstore")
	ErrJWKSNotFound      = errors.New("empty JSON Web Key Set payload")
	ErrJWKNotFound       = errors.New("no JSON Web Key found with matching KeyID (`kid`)")
	ErrJWKSInvalid       = errors.New("invalid JSON Web Key")
	ErrJWKSTypeMismatch  = errors.New("priv/pub JSON Web Key mismatch")
	ErrMultipleHeaders   = errors.New("JWT signature must have only one header")
)

// JSONWebKeyStore is the interface to for storing JSON Web Keys.
type JSONWebKeyStore interface {
	Get(key interface{}) (value interface{}, ok bool)
	Add(key, value interface{})
}

const (
	defaultMaxBodySize = 1024 * 1024 * 4
	defaultJWKSPath    = "/.well-known/pomerium/jwks.json"
)

type Verifier struct {
	staticJWKSEndpoint string
	datastore          JSONWebKeyStore
	logger             *log.Logger
	httpClient         *http.Client
	expected           *jwt.Expected
}

// Options are the configurations for an attestation.
type Options struct {
	// JWKSEndpoint is the static JWKS endpoint to use.
	// If unset, the JWKS endpoint will be inferred from the audience claim on the
	// unverified JWT. Any discovered keys will be trusted on first used (TOFU).
	JWKSEndpoint string
	// Datastore is required and is where JSON Web Keys will be cached.
	Datastore JSONWebKeyStore
	// HTTPClient is an optional custom http client which you can provide.
	HTTPClient *http.Client
	// Logger is an optional custom logger which you provide.
	Logger *log.Logger
	// Expected defines values used for protected claims validation.
	// If field has zero value then validation is skipped.
	Expected *jwt.Expected
}

// New creates a new pomerium Verifier which can be used to verify a JWT token against a
// public JWKS endpoint(s).
func New(o *Options) (*Verifier, error) {
	if o.Datastore == nil {
		return nil, ErrDatastoreRequired
	}
	v := Verifier{
		datastore:  o.Datastore,
		logger:     o.Logger,
		httpClient: o.HTTPClient,
	}
	if v.logger == nil {
		v.logger = log.New(os.Stderr, "", log.LstdFlags)
	}
	if v.httpClient == nil {
		v.httpClient = http.DefaultClient
	}
	if o.JWKSEndpoint != "" {
		u, err := url.Parse(o.JWKSEndpoint)
		if err != nil {
			return nil, err
		}
		v.staticJWKSEndpoint = u.String()
	}
	if o.Expected != nil {
		v.expected = o.Expected
	}

	return &v, nil
}

// Identity is a Pomerium attested identity.
type Identity struct {
	jwt.Claims          // standard JWT claims
	Groups     []string `json:"groups,omitempty"`
	User       string   `json:"user,omitempty"`
	Email      string   `json:"email,omitempty"`
	RawJWT     string   `json:"raw_jwt,omitempty"`
	PublicKey  string   `json:"public_key,omitempty"`
}

// GetIdentity takes a raw JWT string and returns a parsed, and validated Identity.
func (v *Verifier) GetIdentity(ctx context.Context, rawJWT string) (*Identity, error) {
	var id Identity
	// get the web signature of the raw jwt
	sig, err := jose.ParseSigned(rawJWT)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse raw JWT: %w", err)
	}

	jsonWebKey, err := v.getJSONWebKeyFromToken(ctx, rawJWT)
	if err != nil {
		return nil, fmt.Errorf("couldn't get json web key: %w", err)
	}

	jwkBytes, err := jsonWebKey.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal json web key: %w", err)
	}

	id.PublicKey = fmt.Sprintf("%s", jwkBytes)

	b, err := sig.Verify(jsonWebKey)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT signature: %w", err)
	}
	err = json.Unmarshal(b, &id)
	if err != nil {
		return nil, fmt.Errorf("couldn't unmarshal JWT signature: %w", err)
	}
	if v.expected != nil {
		err = id.Validate(*v.expected)
		if err != nil {
			return nil, fmt.Errorf("unexpected claim: %w", err)
		}
	}
	return &id, nil
}

func (v *Verifier) getJSONWebKeyFromToken(ctx context.Context, rawJWT string) (*jose.JSONWebKey, error) {
	tok, err := jwt.ParseSigned(rawJWT)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT: %w", err)
	}

	if len(tok.Headers) != 1 {
		return nil, ErrMultipleHeaders
	}
	h := tok.Headers[0]
	if val, ok := v.datastore.Get(h.KeyID); ok {
		return val.(*jose.JSONWebKey), nil
	}

	verifyEndpoint := v.staticJWKSEndpoint
	if verifyEndpoint == "" {
		out := jwt.Claims{}
		if err := tok.UnsafeClaimsWithoutVerification(&out); err != nil {
			return nil, fmt.Errorf("couldn't get json web key: %w", err)
		}
		u, err := url.Parse(out.Issuer)
		if err != nil {
			return nil, err
		}
		if u.Scheme == "" {
			u.Scheme = "https"
		}
		if u.Path == "" {
			u.Path = defaultJWKSPath
		}

		verifyEndpoint = u.String()
		v.logger.Printf("KeyID: %s not found, fetching jwks endpoint: %s", h.KeyID, verifyEndpoint)
	}
	return v.fetchJWKSFromRemote(ctx, verifyEndpoint, h.KeyID)
}

func (v *Verifier) fetchJWKSFromRemote(ctx context.Context, u, keyID string) (*jose.JSONWebKey, error) {
	val, err := v.requestJWKS(ctx, u)
	if err != nil {
		return nil, err
	}
	var found bool
	var foundKey jose.JSONWebKey
	for i := range val.Keys {
		jwk := val.Keys[i]
		if jwk.KeyID == keyID {
			found = true
			foundKey = jwk
		}
		v.datastore.Add(jwk.KeyID, &jwk)
	}
	if !found {
		return nil, ErrJWKNotFound
	}
	return &foundKey, nil
}

func (v *Verifier) requestJWKS(ctx context.Context, endpoint string) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	res, err := v.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = res.Body.Close() }()
	bs, err := ioutil.ReadAll(io.LimitReader(res.Body, defaultMaxBodySize))
	if err != nil {
		return nil, err
	}

	return parseJWKS(bs, true)
}

func parseJWKS(bs []byte, pub bool) (*jose.JSONWebKeySet, error) {
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(bs, &jwks); err != nil {
		return nil, err
	}
	if len(jwks.Keys) < 1 {
		return nil, ErrJWKSNotFound
	}

	for _, j := range jwks.Keys {
		if !j.Valid() {
			return nil, ErrJWKSInvalid
		}
		if j.IsPublic() != pub {
			return nil, ErrJWKSTypeMismatch
		}
	}

	return &jwks, nil
}
