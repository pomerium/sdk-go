package sdk_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/sdk-go"
	"github.com/pomerium/sdk-go/internal/config"
)

func TestClient(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Pomerium API_TOKEN", r.Header.Get("Authorization"))
		assert.Equal(t, "/pomerium.config.ConfigService/GetServerInfo", r.URL.Path)
		w.Header().Set("Content-Type", "application/proto")
		bs, err := proto.Marshal(&config.GetServerInfoResponse{
			ServerType: config.ServerType_SERVER_TYPE_CORE,
			Version:    "v1.2.3",
		})
		require.NoError(t, err)
		w.Write(bs)
	}))

	client := sdk.NewClient(
		sdk.WithAPIToken("API_TOKEN"),
		sdk.WithURL(srv.URL),
	)
	res, err := client.GetServerInfo(t.Context(), connect.NewRequest(&config.GetServerInfoRequest{}))
	if assert.NoError(t, err) {
		assert.Equal(t, config.ServerType_SERVER_TYPE_CORE, res.Msg.GetServerType())
		assert.Equal(t, "v1.2.3", res.Msg.GetVersion())
	}
}
