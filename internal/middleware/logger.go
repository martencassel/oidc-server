package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
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

func prettyColorJSON(data []byte) (string, error) {
	var buf bytes.Buffer
	err := json.Indent(&buf, data, "", "  ")
	if err != nil {
		return "", err
	}
	return cYellow + buf.String() + cReset, nil
}

// Response recorder
type bodyWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w bodyWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

// Gin middleware
func RequestResponseLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// --- REQUEST ---
		fmt.Printf("%s%s→ REQUEST%s\n", cBlue, cBold, cReset)
		fmt.Printf("%s%s %s%s\n", cBlue, c.Request.Method, c.Request.URL.String(), cReset)
		fmt.Printf("%sHeaders:%s\n%s", cBlue, cReset, formatHeaders(c.Request.Header))

		// Read request body safely
		var reqBody []byte
		if c.Request.Body != nil {
			reqBody, _ = ioutil.ReadAll(c.Request.Body)
			c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(reqBody))
		}

		if len(reqBody) > 0 {
			ct := c.Request.Header.Get("Content-Type")
			if strings.Contains(ct, "application/json") {
				if pretty, err := prettyColorJSON(reqBody); err == nil {
					fmt.Printf("%sJSON Body:%s\n%s\n", cYellow, cReset, pretty)
				} else {
					fmt.Printf("%sBody:%s\n%s\n", cYellow, cReset, string(reqBody))
				}
			} else {
				fmt.Printf("%sBody:%s\n%s\n", cYellow, cReset, string(reqBody))
			}
		}

		// --- RESPONSE CAPTURE ---
		bw := &bodyWriter{body: bytes.NewBufferString(""), ResponseWriter: c.Writer}
		c.Writer = bw

		c.Next()

		// --- RESPONSE ---
		fmt.Printf("%s%s← RESPONSE%s\n", cGreen, cBold, cReset)
		fmt.Printf("%s%d %s%s (%s)\n", cGreen, bw.Status(), http.StatusText(bw.Status()), cReset, time.Since(start))
		fmt.Printf("%sHeaders:%s\n%s", cGreen, cReset, formatHeaders(bw.Header()))

		respBody := bw.body.Bytes()
		if len(respBody) > 0 {
			ct := bw.Header().Get("Content-Type")
			if strings.Contains(ct, "application/json") {
				if pretty, err := prettyColorJSON(respBody); err == nil {
					fmt.Printf("%sJSON Body:%s\n%s\n", cYellow, cReset, pretty)
				} else {
					fmt.Printf("%sBody:%s\n%s\n", cYellow, cReset, string(respBody))
				}
			} else {
				fmt.Printf("%sBody:%s\n%s\n", cYellow, cReset, string(respBody))
			}
		}
	}
}
