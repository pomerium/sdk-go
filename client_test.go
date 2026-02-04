package sdk_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/sdk-go"
	"github.com/pomerium/sdk-go/proto/pomerium"
)

func TestClient(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	var tokenCallCnt atomic.Int64
	mux.HandleFunc("POST /api/v0/token", func(w http.ResponseWriter, r *http.Request) {
		switch tokenCallCnt.Add(1) {
		case 1:
			json.NewEncoder(w).Encode(map[string]any{
				"expiresInSeconds": "1",
				"idToken":          "ID_TOKEN_1",
			})
		default:
			json.NewEncoder(w).Encode(map[string]any{
				"expiresInSeconds": "3600",
				"idToken":          "ID_TOKEN_2",
			})
		}
	})
	mux.HandleFunc("POST /pomerium.config.ConfigService/GetServerInfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/proto")
		bs, err := proto.Marshal(&pomerium.GetServerInfoResponse{
			ServerType: pomerium.ServerType_SERVER_TYPE_ZERO,
			Version:    "v1.2.3",
		})
		require.NoError(t, err)
		w.Write(bs)
	})
	mux.HandleFunc("POST /pomerium.config.ConfigService/ListPolicies", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Pomerium ID_TOKEN_1", r.Header.Get("Authorization"))

		w.Header().Set("Content-Type", "application/proto")
		bs, err := proto.Marshal(&pomerium.ListPoliciesResponse{})
		require.NoError(t, err)
		w.Write(bs)
	})
	mux.HandleFunc("POST /pomerium.config.ConfigService/ListRoutes", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Pomerium ID_TOKEN_2", r.Header.Get("Authorization"))

		w.Header().Set("Content-Type", "application/proto")
		bs, err := proto.Marshal(&pomerium.ListRoutesResponse{})
		require.NoError(t, err)
		w.Write(bs)
	})
	mux.HandleFunc("POST /pomerium.config.ConfigService/ListSettings", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Pomerium ID_TOKEN_2", r.Header.Get("Authorization"))

		w.Header().Set("Content-Type", "application/proto")
		bs, err := proto.Marshal(&pomerium.ListSettingsResponse{})
		require.NoError(t, err)
		w.Write(bs)
	})
	srv := httptest.NewServer(mux)

	client := sdk.NewClient(
		sdk.WithAPIToken("API_TOKEN"),
		sdk.WithURL(srv.URL),
	)
	res1, err := client.GetServerInfo(t.Context(), connect.NewRequest(&pomerium.GetServerInfoRequest{}))
	if assert.NoError(t, err) {
		assert.Equal(t, pomerium.ServerType_SERVER_TYPE_ZERO, res1.Msg.GetServerType())
		assert.Equal(t, "v1.2.3", res1.Msg.GetVersion())
	}
	res2, err := client.ListPolicies(t.Context(), connect.NewRequest(&pomerium.ListPoliciesRequest{}))
	if assert.NoError(t, err) {
		assert.NotNil(t, res2)
	}
	res3, err := client.ListRoutes(t.Context(), connect.NewRequest(&pomerium.ListRoutesRequest{}))
	if assert.NoError(t, err) {
		assert.NotNil(t, res3)
	}
	res4, err := client.ListSettings(t.Context(), connect.NewRequest(&pomerium.ListSettingsRequest{}))
	if assert.NoError(t, err) {
		assert.NotNil(t, res4)
	}
}
