package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"connectrpc.com/connect"

	"github.com/pomerium/sdk-go/proto/pomerium"
)

// tokenMinTTL is the minimum TTL needed to re-use a token
const tokenMinTTL = time.Minute

type zeroToken struct {
	expiry  time.Time
	idToken string
}

// A Client interacts with the config service.
type Client interface {
	pomerium.ConfigServiceClient
}

type clientConfig struct {
	apiToken      string
	clientOptions []connect.ClientOption
	httpClient    connect.HTTPClient
	url           string
}

// A ClientOption customizes the client config.
type ClientOption func(cfg *clientConfig)

// WithAPIToken sets the api token in the client config.
func WithAPIToken(apiToken string) ClientOption {
	return func(cfg *clientConfig) {
		cfg.apiToken = apiToken
	}
}

// WithConnectClientOptions appends connect client options to the client config.
func WithConnectClientOptions(options ...connect.ClientOption) ClientOption {
	return func(cfg *clientConfig) {
		cfg.clientOptions = append(cfg.clientOptions, options...)
	}
}

// WithHTTPClient sets the HTTP client to use in the client config. It defaults
// to the default HTTP client.
func WithHTTPClient(httpClient connect.HTTPClient) ClientOption {
	return func(cfg *clientConfig) {
		cfg.httpClient = httpClient
	}
}

// WithURL sets the url in the client config. It defaults to the Pomerium Zero
// API.
func WithURL(url string) ClientOption {
	return func(cfg *clientConfig) {
		cfg.url = url
	}
}

func getClientConfig(options ...ClientOption) *clientConfig {
	cfg := new(clientConfig)
	WithHTTPClient(http.DefaultClient)(cfg)
	WithURL("https://console.pomerium.app")(cfg)
	for _, o := range options {
		o(cfg)
	}
	return cfg
}

type client struct {
	cfg *clientConfig
	pomerium.ConfigServiceClient

	serverType *cachedValue[pomerium.ServerType]
	zeroToken  *cachedValue[zeroToken]
}

// NewClient creates a new client.
func NewClient(options ...ClientOption) Client {
	c := &client{
		cfg: getClientConfig(options...),
	}
	c.ConfigServiceClient = pomerium.NewConfigServiceClient(c.cfg.httpClient, c.cfg.url,
		connect.WithInterceptors(connect.UnaryInterceptorFunc(c.authenticationInterceptor)),
		connect.WithClientOptions(c.cfg.clientOptions...),
	)
	c.serverType = newCachedValue(c.loadServerType, func(_ pomerium.ServerType) bool {
		return true
	})
	c.zeroToken = newCachedValue(c.loadZeroToken, func(t zeroToken) bool {
		return t.expiry.After(time.Now().Add(tokenMinTTL))
	})
	return c
}

func (c *client) authenticationInterceptor(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		// skip adding authentication for this endpoint
		if req.Spec().Procedure == "/pomerium.config.ConfigService/GetServerInfo" {
			return next(ctx, req)
		}

		token, err := c.getToken(ctx)
		if err != nil {
			return nil, err
		}
		if token != "" {
			req.Header().Set("Authorization", "Pomerium "+token)
		}
		return next(ctx, req)
	}
}

func (c *client) getToken(ctx context.Context) (string, error) {
	// determine what kind of server we're dealing with
	serverType, err := c.serverType.Get(ctx)
	if err != nil {
		return "", err
	}

	// use the api token directly for non-zero servers
	if serverType != pomerium.ServerType_SERVER_TYPE_ZERO {
		return c.cfg.apiToken, nil
	}

	// retrieve the id token from zero
	zeroToken, err := c.zeroToken.Get(ctx)
	if err != nil {
		return "", err
	}
	return zeroToken.idToken, nil
}

func (c *client) loadServerType(ctx context.Context) (pomerium.ServerType, error) {
	res, err := c.GetServerInfo(ctx, connect.NewRequest(&pomerium.GetServerInfoRequest{}))
	if err != nil {
		return pomerium.ServerType_SERVER_TYPE_UNKNOWN, err
	}
	return res.Msg.GetServerType(), nil
}

func (c *client) loadZeroToken(ctx context.Context) (zeroToken, error) {
	now := time.Now()

	data, err := json.Marshal(map[string]any{"refreshToken": c.cfg.apiToken})
	if err != nil {
		return zeroToken{}, fmt.Errorf("error marshaling refresh token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.url+"/api/v0/token", bytes.NewReader(data))
	if err != nil {
		return zeroToken{}, fmt.Errorf("error creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := c.cfg.httpClient.Do(req)
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
