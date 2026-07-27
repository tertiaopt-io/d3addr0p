// Package config loads gateway configuration from the environment. No secrets are logged.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	// ListenAddr is the loopback address Apache mod_proxy_wstunnel forwards to.
	ListenAddr string
	// MaxPayloadBytes caps an envelope payload. At M3 this becomes the largest fixed bucket.
	MaxPayloadBytes int
	// PendingSweep is how often expired undelivered blobs are reaped.
	PendingSweep time.Duration
	// AllowedOrigins controls WebSocket Origin checking. Empty (default) means same-origin only,
	// which compares the browser's Origin against the request Host. Behind a reverse proxy the
	// forwarded Host is the loopback address, so it will NOT match the public Origin: set
	// DD_ALLOWED_ORIGINS to the public host (e.g. "d3addr0p.com") in production. A comma-separated
	// host pattern list is allowed, or "*" to skip the check entirely (DEV ONLY).
	AllowedOrigins string
	// PingInterval keeps idle WebSockets warm through proxies (Cloudflare drops idle connections
	// after ~100s). 0 disables. Set via DD_WS_PING_SECONDS.
	PingInterval time.Duration
	// MaxConns caps concurrent WebSocket connections so one source cannot exhaust the relay by
	// opening sockets. Set via DD_MAX_CONNS; 0 disables the cap.
	MaxConns int
	// PubRate caps messages per second ONE connection may publish/relay (token bucket, burst 2x),
	// so a runaway client cannot saturate the bus. Set via DD_PUB_RATE; 0 disables the cap.
	PubRate float64
	// SubjectRate caps messages per second landing in ONE recipient mailbox across ALL connections
	// (token bucket, burst 2x): the mailbox-flood guard. Set via DD_SUBJECT_RATE; 0 disables it.
	SubjectRate float64
	// CtrlRate caps Subscribe frames per second on ONE connection (token bucket, burst 4x): a backstop
	// against subscription flooding (each subscribe spawns a goroutine + channel). Acks are exempt.
	// Set via DD_CTRL_RATE; 0 disables it.
	CtrlRate float64
	// MaxConnsPerIP caps concurrent connections from one client IP. Set via DD_MAX_CONNS_PER_IP; 0
	// (default) disables it. Only safe to enable behind a firewalled origin plus DD_CLIENT_IP_HEADER
	// (otherwise the key is client-spoofable). See ws.Handler.MaxConnsPerIP.
	MaxConnsPerIP int
	// ClientIPHeader names the trusted header carrying the real client IP (e.g. "CF-Connecting-IP").
	// Set via DD_CLIENT_IP_HEADER; empty uses the direct peer address.
	ClientIPHeader string
}

func Load() (Config, error) {
	c := Config{
		ListenAddr:      env("DD_LISTEN_ADDR", "127.0.0.1:8443"),
		MaxPayloadBytes: 65536,
		PendingSweep:    time.Second,
		AllowedOrigins:  env("DD_ALLOWED_ORIGINS", ""),
		PingInterval:    45 * time.Second,
		MaxConns:        2048,
		// Defaults sized for chat: 20 msg/s sustained (burst 40) is far above human typing and the
		// WebRTC signaling bursts (file/call setup is a handful of frames), and far below a flood.
		PubRate:     20,
		SubjectRate: 20,
		// Control frames (subscribe/ack) are cheap map ops; 200/s sustained (burst 800, above the
		// 512-subscription reconnect burst) only trips on pathological flooding.
		CtrlRate:       200,
		ClientIPHeader: env("DD_CLIENT_IP_HEADER", ""),
	}
	if v := os.Getenv("DD_PUB_RATE"); v != "" {
		n, err := strconv.ParseFloat(v, 64)
		if err != nil || n < 0 {
			return Config{}, fmt.Errorf("DD_PUB_RATE invalid: %q", v)
		}
		c.PubRate = n
	}
	if v := os.Getenv("DD_SUBJECT_RATE"); v != "" {
		n, err := strconv.ParseFloat(v, 64)
		if err != nil || n < 0 {
			return Config{}, fmt.Errorf("DD_SUBJECT_RATE invalid: %q", v)
		}
		c.SubjectRate = n
	}
	if v := os.Getenv("DD_MAX_CONNS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return Config{}, fmt.Errorf("DD_MAX_CONNS invalid: %q", v)
		}
		c.MaxConns = n
	}
	if v := os.Getenv("DD_CTRL_RATE"); v != "" {
		n, err := strconv.ParseFloat(v, 64)
		if err != nil || n < 0 {
			return Config{}, fmt.Errorf("DD_CTRL_RATE invalid: %q", v)
		}
		c.CtrlRate = n
	}
	if v := os.Getenv("DD_MAX_CONNS_PER_IP"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return Config{}, fmt.Errorf("DD_MAX_CONNS_PER_IP invalid: %q", v)
		}
		c.MaxConnsPerIP = n
	}
	if v := os.Getenv("DD_MAX_PAYLOAD_BYTES"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return Config{}, fmt.Errorf("DD_MAX_PAYLOAD_BYTES invalid: %q", v)
		}
		c.MaxPayloadBytes = n
	}
	if v := os.Getenv("DD_WS_PING_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return Config{}, fmt.Errorf("DD_WS_PING_SECONDS invalid: %q", v)
		}
		c.PingInterval = time.Duration(n) * time.Second
	}
	return c, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
