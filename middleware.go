package sdk

import (
	"context"
	"errors"
	"net/http"
)

const (
	defaultAttestationHeader     = "x-pomerium-jwt-assertion"
	defaultAttestationQueryParam = "jwt"
)

var ErrTokenNotFound = errors.New("attestation token not found")

// AddIdentityToRequest is http middleware handler that -- given an attestation instance -- will
// find, parse, verify, and inject a Pomerium identity into the request context.
//
// Nota bene: it is up to the subsequent HTTP Middleware (or handler) to handle any error.
//
// This middleware will search for a JWT token in a http request, in the order:
//
//   1. 'x-pomerium-jwt-assertion' request header injected by pomerium
//   2. 'jwt' URI query parameter
//
// The first JWT string that is found as a query parameter or authorization header
// is then decoded and an **Identity** struct (or any error) is then set on the request context.
//
// The Verifier always calls the next http handler in sequence. Typically, the next middleware
// will check the request context's jwt token and error to prepare a custom
// http response.
func AddIdentityToRequest(a *Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return AddIdentityToRequestWithFn(a, TokenFromHeader, TokenFromQuery)(next)
	}
}

// AddIdentityToRequestWithFn is equivalent to AddIdentityToRequest but supports passing in custom finder functions.
func AddIdentityToRequestWithFn(a *Verifier, findTokenFns ...func(r *http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		hfn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			token, err := getIdentityFromRequest(a, r, findTokenFns...)
			ctx = NewContext(ctx, token, err)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(hfn)
	}
}

func getIdentityFromRequest(a *Verifier, r *http.Request, findTokenFns ...func(r *http.Request) string) (*Identity, error) {
	var tokenString string
	for _, fn := range findTokenFns {
		tokenString = fn(r)
		if tokenString != "" {
			break
		}
	}
	if tokenString == "" {
		return nil, ErrTokenNotFound
	}

	return a.GetIdentity(r.Context(), tokenString)
}

// TokenFromHeader tries to retrieve the token string from the
// ""x-pomerium-jwt-assertion" header.
func TokenFromHeader(r *http.Request) string {
	return r.Header.Get(defaultAttestationHeader)
}

// TokenFromQuery tries to retrieve the token string from the "jwt" URI
// query parameter.
func TokenFromQuery(r *http.Request) string {
	return r.FormValue(defaultAttestationQueryParam)
}

var (
	IdentityCtxKey = &contextKey{"Token"}
	ErrorCtxKey    = &contextKey{"Error"}
)

func NewContext(ctx context.Context, t *Identity, err error) context.Context {
	ctx = context.WithValue(ctx, IdentityCtxKey, t)
	ctx = context.WithValue(ctx, ErrorCtxKey, err)
	return ctx
}

func FromContext(ctx context.Context) (id *Identity, err error) {
	id, _ = ctx.Value(IdentityCtxKey).(*Identity)
	err, _ = ctx.Value(ErrorCtxKey).(error)
	return
}

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation. This technique
// for defining context keys was copied from Go 1.7's new use of context in net/http.
type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "pomerium context value " + k.name
}
