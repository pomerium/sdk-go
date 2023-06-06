package sdk

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"

	"github.com/go-jose/go-jose/v3"
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
	var result struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(bs, &result); err != nil {
		return nil, err
	}

	var keys []jose.JSONWebKey
	for _, rawKey := range result.Keys {
		var key jose.JSONWebKey
		if err := json.Unmarshal(rawKey, &key); err != nil {
			// ignore invalid keys
			continue
		}

		if key.Valid() && key.IsPublic() == pub {
			keys = append(keys, key)
		}
	}

	if len(keys) < 1 {
		return nil, ErrJWKSNotFound
	}
	return &jose.JSONWebKeySet{
		Keys: keys,
	}, nil
}
