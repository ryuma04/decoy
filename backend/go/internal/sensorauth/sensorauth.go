// Package sensorauth signs and verifies sensor requests (04 §A Auth). Shared by core and every decoy.
package sensorauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	HeaderSensor    = "X-DSOC-Sensor"
	HeaderTimestamp = "X-DSOC-Timestamp"
	HeaderSignature = "X-DSOC-Signature"
	MaxSkew         = 120 * time.Second
)

// Signature = hex(HMAC_SHA256(key, timestamp + "\n" + method + "\n" + path + "\n" + sha256hex(body))).
func Signature(key, timestamp, method, path string, body []byte) string {
	sum := sha256.Sum256(body)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(timestamp + "\n" + strings.ToUpper(method) + "\n" + path + "\n" + hex.EncodeToString(sum[:])))
	return hex.EncodeToString(mac.Sum(nil))
}

// Sign sets the three auth headers on req (body must be the exact bytes sent).
func Sign(req *http.Request, sensorID, key string, body []byte, now time.Time) {
	ts := now.UTC().Format(time.RFC3339)
	req.Header.Set(HeaderSensor, sensorID)
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderSignature, Signature(key, ts, req.Method, req.URL.Path, body))
}

var (
	ErrMissing   = errors.New("missing auth headers")
	ErrUnknown   = errors.New("unknown sensor")
	ErrSkew      = errors.New("timestamp outside allowed window")
	ErrSignature = errors.New("bad signature")
)

// Verify checks the headers of r against keys (sensor id -> key) and returns the sensor id.
func Verify(r *http.Request, body []byte, keys map[string]string, now time.Time) (string, error) {
	id, ts, sig := r.Header.Get(HeaderSensor), r.Header.Get(HeaderTimestamp), r.Header.Get(HeaderSignature)
	if id == "" || ts == "" || sig == "" {
		return "", ErrMissing
	}
	key, ok := keys[id]
	if !ok {
		return "", ErrUnknown
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return "", ErrSkew
	}
	if d := now.Sub(t); d > MaxSkew || d < -MaxSkew {
		return "", ErrSkew
	}
	want := Signature(key, ts, r.Method, r.URL.Path, body)
	got, err := hex.DecodeString(sig)
	if err != nil {
		return "", ErrSignature
	}
	wantB, _ := hex.DecodeString(want)
	if !hmac.Equal(got, wantB) {
		return "", ErrSignature
	}
	return id, nil
}
