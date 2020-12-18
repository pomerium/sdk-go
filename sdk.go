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

// JSONWebKeyStore is the interface to support storing multiple web keys
// for more than one authenticate services.
type JSONWebKeyStore interface {
	Get(key interface{}) (value interface{}, ok bool)
	Add(key, value interface{})
}

const (
	defaultAttestationHeader     = "x-pomerium-jwt-assertion"
	defaultAttestationQueryParam = "jwt"
	defaultMaxBodySize           = 1024 * 1024 * 4
	defaultJWKSPath              = "/.well-known/pomerium/jwks.json"
)

// Attestation is r
type Attestation struct {
	StaticJSONWebKey *jose.JSONWebKey

	attestationHeader     string
	attestationQueryParam string
	maxBodySize           int64
	datastore             JSONWebKeyStore
	logger                *log.Logger
	httpClient            *http.Client
}

// Options are the configurations for Pomerium's attestation.
type Options struct {
	// 	AttestationHeader is the attestation header to look for the attestation JWT.
	AttestationHeader string
	// 	AttestationQueryParam is the query param to look for the attestation JWT.
	AttestationQueryParam string
	// MaxBodySize is the max size to read from the JWKS endpoint.
	MaxBodySize int64
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

// New creates a new Attestation.
func New(ctx context.Context, o *Options) (*Attestation, error) {
	if (o.Datastore == nil && o.JWKSEndpoint == "") || o.Datastore != nil && o.JWKSEndpoint != "" {
		return nil, errors.New("pomerium/sdk: either JWKS endpoint or datstore must be set.")
	}

	a := Attestation{
		attestationHeader:     o.AttestationHeader,
		attestationQueryParam: o.AttestationQueryParam,
		maxBodySize:           o.MaxBodySize,
		datastore:             o.Datastore,
		logger:                o.Logger,
		httpClient:            o.HTTPClient,
	}
	// set unassigned to defaults
	if a.logger == nil {
		a.logger = log.New(os.Stderr, "", log.LstdFlags)
	}
	if a.httpClient == nil {
		a.httpClient = http.DefaultClient
	}
	if a.attestationHeader == "" {
		a.attestationHeader = defaultAttestationHeader
	}
	if a.attestationQueryParam == "" {
		a.attestationQueryParam = defaultAttestationQueryParam
	}

	if a.maxBodySize == 0 {
		a.maxBodySize = defaultMaxBodySize
	}

	if o.JWKSEndpoint != "" {
		var err error
		a.StaticJSONWebKey, err = a.getJSONWebKey(ctx, o.JWKSEndpoint)
		if err != nil {
			return nil, err
		}
	}
	return &a, nil
}

// Identity is a pomerium attested identity.
type Identity struct {
	jwt.Claims          // standard JWT claims
	Groups     []string `json:"groups,omitempty"`
	User       string   `json:"user,omitempty"`
	Email      string   `json:"email,omitempty"`
	RawJWT     string   `json:"raw_jwt,omitempty"`
	PublicKey  string   `json:"public_key,omitempty"`
}

// VerifyRequest takes a http request and returns a verified identity, if valid.
func (a *Attestation) VerifyRequest(r *http.Request) (*Identity, error) {
	jwt := getRawJWT(r)
	if len(jwt) == 0 {
		return nil, errors.New("attestation header / queryparam not found")
	}
	return a.Verify(r.Context(), jwt)
}

// VerifyRequest takes a raw pomerium JWT and returns a verified identity, if valid.
func (a *Attestation) Verify(ctx context.Context, rawJWT string) (*Identity, error) {
	var id Identity
	// get the web signature of the raw jwt
	sig, err := jose.ParseSigned(rawJWT)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse raw JWT: %w", err)
	}
	// if set, use the static JSON Web Token
	jsonWebKey := a.StaticJSONWebKey
	// otherwise, grab it at runtime and TOFU
	if jsonWebKey == nil {
		jsonWebKey, err = a.getJSONWebKeyFromToken(ctx, rawJWT)
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

// getRawJWT checks first for the query param, and then the attestation header
// for pomerium's attestation jwt. If non exists, returns ""
func getRawJWT(r *http.Request) string {
	if jwt := r.FormValue(defaultAttestationQueryParam); jwt != "" {
		return jwt
	}
	return r.Header.Get(defaultAttestationHeader)
}

func (a *Attestation) getJSONWebKeyFromToken(ctx context.Context, rawJWT string) (*jose.JSONWebKey, error) {
	tok, err := jwt.ParseSigned(rawJWT)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT: %w", err)
	}
	out := jwt.Claims{}
	if err := tok.UnsafeClaimsWithoutVerification(&out); err != nil {
		return nil, fmt.Errorf("couldn't get json web key: %w", err)
	}

	if val, ok := a.datastore.Get(out.ID); ok {
		return val.(*jose.JSONWebKey), nil
	}

	u := url.URL{
		Scheme: "https",
		Host:   out.Issuer,
		Path:   defaultJWKSPath,
	}
	val, err := a.getJSONWebKey(ctx, u.String())
	if err != nil {
		return nil, err
	}
	a.datastore.Add(out.ID, val)
	a.logger.Printf("added %s to the keystore", out.ID)
	return val, nil
}

func (a *Attestation) getJSONWebKey(ctx context.Context, endpoint string) (*jose.JSONWebKey, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	res, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = res.Body.Close() }()
	bs, err := ioutil.ReadAll(io.LimitReader(res.Body, defaultMaxBodySize))
	if err != nil {
		return nil, err
	}
	log.Printf("wb %s", bs)

	return loadJSONWebKey(bs, true)
}

func loadJSONWebKey(bs []byte, pub bool) (*jose.JSONWebKey, error) {
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(bs, &jwks); err != nil {
		return nil, err
	}
	if len(jwks.Keys) < 1 {
		return nil, errors.New("no JSON Web Key found")
	}
	jwk := jwks.Keys[0]
	if !jwk.Valid() {
		return nil, errors.New("invalid JSON Web Key")
	}
	if jwk.IsPublic() != pub {
		return nil, errors.New("priv/pub JSON Web Key mismatch")
	}
	return &jwk, nil
}
