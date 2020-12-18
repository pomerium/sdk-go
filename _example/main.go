package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/pomerium/sdk-go/_example/verify"
)

const defaultAddr = ":80"

var (
	addr     string
	certFile string
	keyFile  string
)

func run() (err error) {
	flag.StringVar(&addr, "addr", defaultAddr, "Address to listen on")
	flag.StringVar(&certFile, "https-cert-file", "", "HTTPS Server certificate file")
	flag.StringVar(&keyFile, "https-key-file", "", "HTTPS Server private key file")

	if addr == defaultAddr && os.Getenv("Addr") != "" {
		addr = os.Getenv("Addr")
	}

	verifier, err := verify.New(1024)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       5 * time.Minute,
		Handler:           verifier.Handler(),
	}

	if certFile != "" && keyFile != "" {
		return srv.ListenAndServeTLS(certFile, keyFile)
	}

	return srv.ListenAndServe()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "pomerium/verifier: error %v", err)
		flag.Usage()
		os.Exit(1)
	}
}
