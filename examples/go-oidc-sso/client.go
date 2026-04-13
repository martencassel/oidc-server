package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

var (
	cReset  = "\033[0m"
	cBlue   = "\033[34m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cRed    = "\033[31m"
	cBold   = "\033[1m"
)

func formatHeaders(h http.Header) string {
	var b strings.Builder
	for k, vals := range h {
		for _, v := range vals {
			fmt.Fprintf(&b, "  %s: %s\n", k, v)
		}
	}
	return b.String()
}

func newLoggedHTTPClient() *http.Client {
	return &http.Client{
		Transport: LoggingTransport{
			Base: http.DefaultTransport,
		},
	}
}

type LoggingTransport struct {
	Base http.RoundTripper
}

func (t LoggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()

	// Clone request so we don't mutate the original
	r2 := req.Clone(req.Context())

	// Log request
	log.Printf("%s%s→ REQUEST%s", cBlue, cBold, cReset)
	log.Printf("%s%s %s%s", cBlue, r2.Method, r2.URL.String(), cReset)
	log.Printf("%sHeaders:%s\n%s", cBlue, cReset, formatHeaders(r2.Header))

	// Perform request
	res, err := t.Base.RoundTrip(r2)
	if err != nil {
		log.Printf("%s%s← ERROR%s %v (%s)", cRed, cBold, cReset, err, time.Since(start))
		return nil, err
	}

	// Log response
	log.Printf("%s%s← RESPONSE%s", cGreen, cBold, cReset)
	log.Printf("%s%d %s%s (%s)", cGreen, res.StatusCode, http.StatusText(res.StatusCode), cReset, time.Since(start))
	log.Printf("%sHeaders:%s\n%s", cGreen, cReset, formatHeaders(res.Header))

	return res, nil
}

func prettyColorJSON(data []byte) (string, error) {
	var buf bytes.Buffer
	err := json.Indent(&buf, data, "", "  ")
	if err != nil {
		return "", err
	}
	return cYellow + buf.String() + cReset, nil
}
