package sdk_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/sdk-go"
)

func TestZeroClient(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v0/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"expiresInSeconds": "3600",
			"idToken":          "ID_TOKEN",
		})
	})
	mux.HandleFunc("POST /api/v0/organizations/ORGANIZATION_ID/clusters/CLUSTER_ID/ping", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Pomerium ID_TOKEN", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"success": true,
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Error("unexpected request", r.Method, r.URL.String())
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)

	client, err := sdk.NewZeroClient(
		sdk.WithAPIToken("API_TOKEN"),
		sdk.WithURL(srv.URL),
	)
	assert.NoError(t, err)

	res, err := client.PingClusterWithResponse(t.Context(), "ORGANIZATION_ID", "CLUSTER_ID")
	assert.NoError(t, err)
	assert.NotNil(t, res.JSON200)
}
