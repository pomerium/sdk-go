package sdk

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"

	jose "gopkg.in/square/go-jose.v2"
)

// EncodeJSONWebKeySetToPEM encodes the key set to PEM format using PKIX, ASN.1 DER form.
func EncodeJSONWebKeySetToPEM(set *jose.JSONWebKeySet) ([]byte, error) {
	var buf bytes.Buffer
	for _, key := range set.Keys {
		der, err := x509.MarshalPKIXPublicKey(key.Key)
		if err != nil {
			return nil, err
		}

		err = pem.Encode(&buf, &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: der,
		})
		if err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// FetchJSONWebKeySet retrieves a JSONWebKeySet from an HTTP endpoint.
func FetchJSONWebKeySet(ctx context.Context, client *http.Client, endpoint string) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()

	bs, err := io.ReadAll(io.LimitReader(res.Body, defaultMaxBodySize))
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
