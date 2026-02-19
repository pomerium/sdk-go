package sdk

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

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

	apiURL, err := url.Parse(c.cfg.url)
	if err != nil {
		return nil, fmt.Errorf("invalid api url: %w", err)
	}

	var target string
	if addrPort, err := netip.ParseAddrPort(apiURL.Host); err == nil {
		if addrPort.Addr().Is4() {
			target = fmt.Sprintf("ipv4:%s:%d", addrPort.Addr().String(), addrPort.Port())
		} else {
			target = fmt.Sprintf("ipv6:%s:%d", addrPort.Addr().String(), addrPort.Port())
		}
	} else if addr, err := netip.ParseAddr(apiURL.Host); err == nil {
		if addr.Is4() {
			target = fmt.Sprintf("ipv4:%s", addr.String())
		} else {
			target = fmt.Sprintf("ipv6:%s", addr.String())
		}
	} else {
		target = fmt.Sprintf("dns:%s", apiURL.Host)
	}

	dialOptions := []grpc.DialOption{
		grpc.WithStreamInterceptor(c.authenticationStreamInterceptor),
		grpc.WithUnaryInterceptor(c.authenticationUnaryInterceptor),
	}

	if apiURL.Scheme == "https" {
		t, ok := c.cfg.httpClient.Transport.(*http.Transport)
		if ok && t.TLSClientConfig != nil {
			dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(t.TLSClientConfig)))
		} else {
			dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(nil)))
		}
	} else {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	cc, err := grpc.NewClient(target, dialOptions...)
	if err != nil {
		return nil, err
	}
	c.DataBrokerServiceClient = pomerium.NewDataBrokerServiceClient(cc)
	return c, nil
}

func (c *coreClient) authenticationStreamInterceptor(
	ctx context.Context,
	desc *grpc.StreamDesc,
	cc *grpc.ClientConn,
	method string,
	streamer grpc.Streamer,
	opts ...grpc.CallOption,
) (grpc.ClientStream, error) {
	headers := make(http.Header)
	err := c.setAuthorizationHeaders(headers)
	if err != nil {
		return nil, err
	}
	for k, vs := range headers {
		for _, v := range vs {
			ctx = metadata.AppendToOutgoingContext(ctx, k, v)
		}
	}
	return streamer(ctx, desc, cc, method, opts...)
}

func (c *coreClient) authenticationUnaryInterceptor(
	ctx context.Context,
	method string,
	req, reply any,
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	headers := make(http.Header)
	err := c.setAuthorizationHeaders(headers)
	if err != nil {
		return err
	}
	for k, vs := range headers {
		for _, v := range vs {
			ctx = metadata.AppendToOutgoingContext(ctx, k, v)
		}
	}
	return invoker(ctx, method, req, reply, cc, opts...)
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
