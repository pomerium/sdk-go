package sdk

import (
	"context"
	"encoding/base64"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"

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
	c.zeroToken = newCachedValue(func(ctx context.Context) (zeroToken, error) {
		return loadZeroToken(ctx, c.cfg)
	}, func(t zeroToken) bool {
		return t.expiry.After(time.Now().Add(tokenMinTTL))
	})
	return c
}

func (c *client) authenticationInterceptor(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		// always pass the api token for this endpoint
		if req.Spec().Procedure == "/pomerium.config.ConfigService/GetServerInfo" {
			req.Header().Set("Authorization", "Pomerium "+c.cfg.apiToken)
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

	switch serverType {
	case pomerium.ServerType_SERVER_TYPE_CORE:
		// if the api token is a shared key, generate a core JWT
		if key, ok := parseTokenAsKey(c.cfg.apiToken); ok {
			return generateCoreJWT(key)
		}
		return c.cfg.apiToken, nil
	case pomerium.ServerType_SERVER_TYPE_ZERO:
		// retrieve the id token from zero
		zeroToken, err := c.zeroToken.Get(ctx)
		if err != nil {
			return "", err
		}
		return zeroToken.idToken, nil
	case pomerium.ServerType_SERVER_TYPE_ENTERPRISE:
		// if the api token is a shared key, generate an enterprise JWT
		if key, ok := parseTokenAsKey(c.cfg.apiToken); ok {
			return generateEnterpriseJWT(key)
		}
		return c.cfg.apiToken, nil
	case pomerium.ServerType_SERVER_TYPE_UNKNOWN:
		fallthrough
	default:
		return c.cfg.apiToken, nil
	}
}

func (c *client) loadServerType(ctx context.Context) (pomerium.ServerType, error) {
	res, err := c.GetServerInfo(ctx, connect.NewRequest(&pomerium.GetServerInfoRequest{}))
	if err != nil {
		return pomerium.ServerType_SERVER_TYPE_UNKNOWN, err
	}
	return res.Msg.GetServerType(), nil
}

func parseTokenAsKey(str string) (key []byte, ok bool) {
	key, err := base64.StdEncoding.DecodeString(str)
	if err != nil || len(key) != 32 {
		return nil, false
	}
	return key, true
}

func generateCoreJWT(key []byte) (string, error) {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}

	return jwt.Signed(sig).Claims(jwt.Claims{
		Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).CompactSerialize()
}

func generateEnterpriseJWT(key []byte) (string, error) {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}

	now := time.Now()
	return jwt.Signed(sig).Claims(jwt.Claims{
		ID:        "014e587b-3f4b-4fcf-90a9-f6ecdf8154af",
		Subject:   "bootstrap-014e587b-3f4b-4fcf-90a9-f6ecdf8154af.pomerium",
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-time.Second)),
	}).CompactSerialize()
}
