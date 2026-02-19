package sdk

import (
	"context"
	"fmt"
	"net/http"

	"connectrpc.com/connect"

	"github.com/pomerium/sdk-go/proto/pomerium"
)

// A CoreClient is a client for a Pomerium core instance.
type CoreClient interface {
	pomerium.DataBrokerServiceClient
}

type coreClient struct {
	cfg *clientConfig
	pomerium.DataBrokerServiceClient
}

// NewCoreClient creates a new CoreClient.
func NewCoreClient(options ...ClientOption) (CoreClient, error) {
	c := &coreClient{
		cfg: getClientConfig(options...),
	}
	c.DataBrokerServiceClient = pomerium.NewDataBrokerServiceClient(c.cfg.httpClient, c.cfg.url,
		connect.WithInterceptors(connect.UnaryInterceptorFunc(c.authenticationInterceptor)),
		connect.WithClientOptions(append([]connect.ClientOption{
			connect.WithGRPC(), // always use gRPC
		}, c.cfg.clientOptions...)...),
	)
	return c, nil
}

func (c *coreClient) authenticationInterceptor(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		err := c.setAuthorizationHeaders(req.Header())
		if err != nil {
			return nil, fmt.Errorf("error setting authorization headers: %w", err)
		}

		return next(ctx, req)
	}
}

func (c *coreClient) setAuthorizationHeaders(headers http.Header) error {
	// if the token is a shared key, generate JWTs and pass those to the API
	if sharedKey, ok := parseTokenAsKey(c.cfg.apiToken); ok {
		// an authenticated route to the databroker will use a special bootstrap user for authentication
		bootstrapJWT, err := generateBootstrapJWT(sharedKey)
		if err != nil {
			return fmt.Errorf("error generating bootstrap JWT from shared key: %w", err)
		}
		headers.Set("Authorization", "Pomerium "+bootstrapJWT)

		// the databroker expects a jwt header
		coreJWT, err := generateGRPCJWT(sharedKey)
		if err != nil {
			return fmt.Errorf("error generating core JWT from shared key: %w", err)
		}
		headers["jwt"] = []string{coreJWT}
	} else {
		headers.Set("Authorization", "Pomerium "+c.cfg.apiToken)
		headers["jwt"] = []string{c.cfg.apiToken}
	}
	return nil
}
