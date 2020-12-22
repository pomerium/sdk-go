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

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	ErrJWKSEndpointOrDatastore = errors.New("must set either an endpoint or datstore")
	ErrJWKSNotFound            = errors.New("no JSON Web Key found")
	ErrJWKSInvalid             = errors.New("invalid JSON Web Key")
	ErrJWKSTypeMismatch        = errors.New("priv/pub JSON Web Key mismatch")
)

// JSONWebKeyStore is the interface to support storing multiple web keys
// for more than one authenticate services.
type JSONWebKeyStore interface {
	Get(key interface{}) (value interface{}, ok bool)
	Add(key, value interface{})
}

const (
	defaultMaxBodySize = 1024 * 1024 * 4
	defaultJWKSPath    = "/.well-known/pomerium/jwks.json"
)

type Verifier struct {
	StaticJSONWebKey *jose.JSONWebKey

	datastore  JSONWebKeyStore
	logger     *log.Logger
	httpClient *http.Client
}

// Options are the configurations for an attestation.
type Options struct {
	// JWKSEndpoint is the static JWKS endpoint to use to verify the attestation JWTs.
	// This setting is mutually exclusive with Datastore.
	JWKSEndpoint string
	// Datastore is the datastore system which implements JSONWebKeyStore that can be used to ad-hoc
	// grab the JSON Web Token. Useful when supporting multiple endpoints, but effectively
	// means verification is TOFU (trust on first use).
	// This setting is mutually exclusive with JWKSEndpoint.
	Datastore JSONWebKeyStore
	// HTTPClient is a custom http client which you provide.
	HTTPClient *http.Client
	// Logger is a custom logger which you provide.
	Logger *log.Logger
}

// New creates a new pomerium Verifier which can be used to verify a JWT token against a
// public JWKS endpoint(s).
//
// If JWKS endpoint option is set, a http request will be made to fetch the JSON Web Token at the
// provided url on creation  and will be static for the lifetime of the attestation instance.
//
// Otherwise, if a datastore is used, verifier will attempt fetch a JSON Web Token ad-hoc and
// trust that token on first use.
func New(ctx context.Context, o *Options) (*Verifier, error) {
	if (o.Datastore == nil && o.JWKSEndpoint == "") || o.Datastore != nil && o.JWKSEndpoint != "" {
		return nil, ErrJWKSEndpointOrDatastore
	}

	v := Verifier{
		datastore:  o.Datastore,
		logger:     o.Logger,
		httpClient: o.HTTPClient,
	}
	// set unassigned to defaults
	if v.logger == nil {
		v.logger = log.New(os.Stderr, "", log.LstdFlags)
	}
	if v.httpClient == nil {
		v.httpClient = http.DefaultClient
	}

	// if JWKS endpoint is set, try to grab the web key from the endpoint now
	if o.JWKSEndpoint != "" {
		var err error
		v.StaticJSONWebKey, err = v.getJSONWebKey(ctx, o.JWKSEndpoint)
		if err != nil {
			return nil, err
		}
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
	// if set, use the static JSON Web Token
	jsonWebKey := v.StaticJSONWebKey
	// otherwise, grab it at runtime and TOFU
	if jsonWebKey == nil {
		jsonWebKey, err = v.getJSONWebKeyFromToken(ctx, rawJWT)
		if err != nil {
			return nil, fmt.Errorf("couldn't get json web key: %w", err)
		}
	}
	// convert the JWKS endpoint payload into JSON
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
	return &id, nil
}

func (v *Verifier) getJSONWebKeyFromToken(ctx context.Context, rawJWT string) (*jose.JSONWebKey, error) {
	tok, err := jwt.ParseSigned(rawJWT)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT: %w", err)
	}
	out := jwt.Claims{}
	if err := tok.UnsafeClaimsWithoutVerification(&out); err != nil {
		return nil, fmt.Errorf("couldn't get json web key: %w", err)
	}

	if val, ok := v.datastore.Get(out.ID); ok {
		return val.(*jose.JSONWebKey), nil
	}

	u := url.URL{
		Scheme: "https",
		Host:   out.Issuer,
		Path:   defaultJWKSPath,
	}
	val, err := v.getJSONWebKey(ctx, u.String())
	if err != nil {
		return nil, err
	}
	v.datastore.Add(out.ID, val)
	v.logger.Printf("added %s to the keystore", out.ID)
	return val, nil
}

func (v *Verifier) getJSONWebKey(ctx context.Context, endpoint string) (*jose.JSONWebKey, error) {

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

	return loadJSONWebKey(bs, true)
}

func loadJSONWebKey(bs []byte, pub bool) (*jose.JSONWebKey, error) {
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(bs, &jwks); err != nil {
		return nil, err
	}
	if len(jwks.Keys) < 1 {
		return nil, ErrJWKSNotFound
	}
	jwk := jwks.Keys[0]
	if !jwk.Valid() {
		return nil, ErrJWKSInvalid
	}
	if jwk.IsPublic() != pub {
		return nil, ErrJWKSTypeMismatch
	}
	return &jwk, nil
}
