package sdk

import (
	"context"
	"encoding/base64"
	"fmt"
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
	httpClient    *http.Client
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
func WithHTTPClient(httpClient *http.Client) ClientOption {
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
		var serverType pomerium.ServerType
		if req.Spec().Procedure == "/pomerium.config.ConfigService/GetServerInfo" {
			// for the GetServerInfo endpoint we always use the unknown server type
			serverType = pomerium.ServerType_SERVER_TYPE_UNKNOWN
		} else {
			// for all other endpoints we call GetServerInfo to determine the server type
			var err error
			serverType, err = c.serverType.Get(ctx)
			if err != nil {
				return nil, fmt.Errorf("error determining server type: %w", err)
			}
		}

		err := c.setAuthorizationHeaders(ctx, req.Header(), serverType)
		if err != nil {
			return nil, fmt.Errorf("error setting authorization headers: %w", err)
		}

		return next(ctx, req)
	}
}

func (c *client) setAuthorizationHeaders(ctx context.Context, headers http.Header, serverType pomerium.ServerType) error {
	// if this is a zero server, swap the token for an id token and add that header
	if serverType == pomerium.ServerType_SERVER_TYPE_ZERO {
		zeroToken, err := c.zeroToken.Get(ctx)
		if err != nil {
			return err
		}
		headers.Set("Authorization", "Pomerium "+zeroToken.idToken)
		return nil
	}

	// if the token is a shared key, generate JWTs and pass those to the API
	if sharedKey, ok := parseTokenAsKey(c.cfg.apiToken); ok {
		// the enterprise console and an authenticated route to the databroker will
		// use a special bootstrap user for authentication
		bootstrapJWT, err := generateBootstrapJWT(sharedKey)
		if err != nil {
			return fmt.Errorf("error generating bootstrap JWT from shared key: %w", err)
		}
		headers.Set("Authorization", "Pomerium "+bootstrapJWT)

		// the databroker expects a jwt header
		if serverType == pomerium.ServerType_SERVER_TYPE_CORE || serverType == pomerium.ServerType_SERVER_TYPE_UNKNOWN {
			coreJWT, err := generateGRPCJWT(sharedKey)
			if err != nil {
				return fmt.Errorf("error generating core JWT from shared key: %w", err)
			}
			headers["jwt"] = []string{coreJWT}
		}
	} else {
		headers.Set("Authorization", "Pomerium "+c.cfg.apiToken)
		headers["jwt"] = []string{c.cfg.apiToken}
	}

	return nil
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

func generateGRPCJWT(key []byte) (string, error) {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}

	return jwt.Signed(sig).Claims(jwt.Claims{
		Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).CompactSerialize()
}

func generateBootstrapJWT(key []byte) (string, error) {
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
