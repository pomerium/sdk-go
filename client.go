package sdk

import (
	"context"
	"net/http"

	"connectrpc.com/connect"

	"github.com/pomerium/sdk-go/proto/pomerium"
)

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

// NewClient creates a new client.
func NewClient(options ...ClientOption) Client {
	cfg := getClientConfig(options...)
	return pomerium.NewConfigServiceClient(cfg.httpClient, cfg.url,
		connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
			return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				if cfg.apiToken != "" {
					req.Header().Set("Authorization", "Pomerium "+cfg.apiToken)
				}
				return next(ctx, req)
			}
		})),
		connect.WithClientOptions(cfg.clientOptions...),
	)
}
