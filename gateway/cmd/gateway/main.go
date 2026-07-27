// Command gateway is the DEAD DROP realtime gateway (ADR-001).
//
// It starts, wires up the in-process bus (ADR-002), terminates client WebSocket connections and
// their protobuf framing (see internal/ws), and exposes a health check. It carries ONLY opaque
// ciphertext envelopes and never holds keys (brief §4.1): every payload is forwarded byte-for-byte,
// there is no sender field (sealed sender), and the process logs nothing per-user or per-message.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/deaddrop/gateway/internal/bus"
	"github.com/deaddrop/gateway/internal/config"
	"github.com/deaddrop/gateway/internal/ws"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	b := bus.New(ctx, cfg.PendingSweep)
	defer b.Close()

	mux := http.NewServeMux()
	// Health only. Deliberately no per-user or per-message detail (§5.10 logs-nothing).
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// WebSocket: ciphertext-only transport over the in-process bus. Apache mod_proxy_wstunnel
	// forwards the (later non-obvious, M3) path here.
	mux.Handle("/ws", &ws.Handler{Bus: b, MaxPayloadBytes: cfg.MaxPayloadBytes, AllowedOrigins: cfg.AllowedOrigins, PingInterval: cfg.PingInterval, MaxConns: cfg.MaxConns, PubRate: cfg.PubRate, SubjectRate: cfg.SubjectRate, CtrlRate: cfg.CtrlRate, MaxConnsPerIP: cfg.MaxConnsPerIP, ClientIPHeader: cfg.ClientIPHeader})

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("gateway listening on %s (bus: in-process)", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server error: %v", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Print("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
		os.Exit(1)
	}
}
