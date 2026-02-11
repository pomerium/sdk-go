package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/pomerium/sdk-go/pkg/zeroapi"
)

type ZeroClient interface {
	zeroapi.ClientWithResponsesInterface
}

type zeroClient struct {
	cfg *clientConfig
	zeroapi.ClientWithResponsesInterface

	zeroToken *cachedValue[zeroToken]
}

func NewZeroClient(options ...ClientOption) (ZeroClient, error) {
	c := &zeroClient{
		cfg: getClientConfig(options...),
	}

	client, err := zeroapi.NewClientWithResponses(c.cfg.url+"/api/v0",
		zeroapi.WithHTTPClient(c.cfg.httpClient),
		zeroapi.WithRequestEditorFn(c.authenticationRequestEditorFn))
	if err != nil {
		return nil, err
	}
	c.ClientWithResponsesInterface = client

	c.zeroToken = newCachedValue(func(ctx context.Context) (zeroToken, error) {
		return loadZeroToken(ctx, c.cfg)
	}, func(t zeroToken) bool {
		return t.expiry.After(time.Now().Add(tokenMinTTL))
	})

	return c, nil
}

func (c *zeroClient) authenticationRequestEditorFn(ctx context.Context, req *http.Request) error {
	token, err := c.zeroToken.Get(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Pomerium "+token.idToken)
	return nil
}

func loadZeroToken(ctx context.Context, cfg *clientConfig) (zeroToken, error) {
	now := time.Now()

	data, err := json.Marshal(map[string]any{"refreshToken": cfg.apiToken})
	if err != nil {
		return zeroToken{}, fmt.Errorf("error marshaling refresh token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.url+"/api/v0/token", bytes.NewBuffer(data))
	if err != nil {
		return zeroToken{}, fmt.Errorf("error creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := cfg.httpClient.Do(req)
	if err != nil {
		return zeroToken{}, fmt.Errorf("error executing token request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode/100 != 2 {
		return zeroToken{}, fmt.Errorf("unexpected status code from zero API: %d", res.StatusCode)
	}

	var resData struct {
		ExpiresInSeconds string `json:"expiresInSeconds"`
		IDToken          string `json:"idToken"`
	}
	err = json.NewDecoder(res.Body).Decode(&resData)
	if err != nil {
		return zeroToken{}, fmt.Errorf("error unmarshaling token response: %w", err)
	}

	expires, err := strconv.ParseInt(resData.ExpiresInSeconds, 10, 64)
	if err != nil {
		return zeroToken{}, fmt.Errorf("error parsing token expiry: %w", err)
	}

	return zeroToken{
		expiry:  now.Add(time.Second * time.Duration(expires)),
		idToken: resData.IDToken,
	}, nil
}
