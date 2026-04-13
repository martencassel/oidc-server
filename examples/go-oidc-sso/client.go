package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
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

	// REQUEST
	log.Printf("%s%s→ REQUEST%s", cBlue, cBold, cReset)
	log.Printf("%s%s %s%s", cBlue, req.Method, req.URL.String(), cReset)
	log.Printf("%sHeaders:%s\n%s", cBlue, cReset, formatHeaders(req.Header))

	res, err := t.Base.RoundTrip(req)
	if err != nil {
		log.Printf("%s%s← ERROR%s %v (%s)", cRed, cBold, cReset, err, time.Since(start))
		return nil, err
	}

	// RESPONSE
	log.Printf("%s%s← RESPONSE%s", cGreen, cBold, cReset)
	log.Printf("%s%d %s%s (%s)", cGreen, res.StatusCode, http.StatusText(res.StatusCode), cReset, time.Since(start))
	log.Printf("%sHeaders:%s\n%s", cGreen, cReset, formatHeaders(res.Header))

	// BODY (pretty JSON if applicable)
	ct := res.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		bodyBytes, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()

		pretty, err := prettyColorJSON(bodyBytes)
		if err != nil {
			log.Printf("%s[raw body]%s\n%s", cYellow, cReset, string(bodyBytes))
		} else {
			log.Printf("%sJSON Body:%s\n%s", cYellow, cReset, pretty)
		}

		// restore body for caller
		res.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

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
