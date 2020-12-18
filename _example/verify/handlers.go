package verify

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strings"

	"github.com/pomerium/sdk-go"
)

type Verify struct {
	pomerium  *sdk.Attestation
	templates *template.Template
}

func New(cacheSize int) (*Verify, error) {
	c, err := NewCache(cacheSize)
	if err != nil {
		return nil, err
	}
	att, err := sdk.New(context.Background(), &sdk.Options{Datastore: c})
	if err != nil {
		return nil, err
	}
	return &Verify{
		pomerium:  att,
		templates: template.Must(NewTemplates()),
	}, nil
}

func (h *Verify) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.html)
	mux.HandleFunc("/health", h.healthCheck)
	mux.HandleFunc("/headers", h.headers)
	mux.HandleFunc("/json", h.json)
	mux.Handle("/assets/", http.StripPrefix("/assets/", MustAssetHandler()))
	return mux
}

func (h *Verify) healthCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, http.StatusText(http.StatusOK))
}

func (h *Verify) html(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	h.templates.ExecuteTemplate(w, "dashboard.html", h.allDetails(r))
}

func (h *Verify) headers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, r.Header)
}

func (h *Verify) json(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.allDetails(r))
}

func (h *Verify) serverInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, r.Header)
}

func (h *Verify) allDetails(r *http.Request) map[string]interface{} {
	a, attestErr := h.pomerium.VerifyRequest(r)
	payload := map[string]interface{}{
		"Request": map[string]interface{}{
			"Origin":   getOrigin(r),
			"Method":   r.Method,
			"URL":      r.URL.RequestURI(),
			"Host":     r.Host,
			"UUID":     uuid(),
			"Hostname": hostname(),
		},
		"PomeriumInfo":    a,
		"PomeriumInfoErr": attestErr,
		"PomeriumHeaders": getPomeriumHeaders(r),
	}
	return payload
}

func getPomeriumHeaders(r *http.Request) http.Header {
	hdrs := r.Header.Clone()
	for v := range r.Header {
		v = strings.ToLower(v)
		if !strings.Contains(v, "x-pomerium-claim") {
			hdrs.Del(v)
		}
	}
	return hdrs
}

func getOrigin(r *http.Request) string {
	origin := r.Header.Get("X-Forwarded-For")
	if origin == "" {
		origin = r.RemoteAddr
	}
	return origin
}

func uuid() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:])
}

func hostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	b := new(bytes.Buffer)
	enc := json.NewEncoder(b)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(b, `{"error":"%s"}`, err)
		return
	}
	w.WriteHeader(code)
	fmt.Fprint(w, b)
}
