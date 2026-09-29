// Command extmcp serves the ExtMCP guardrail policy over gRPC (h2c).
package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/ably77/extmcp-guardrails/gen/extmcp"
	"github.com/ably77/extmcp-guardrails/internal/policy"
	"github.com/ably77/extmcp-guardrails/internal/server"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	level := slog.LevelInfo
	if os.Getenv("LOG_LEVEL") == "debug" {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	path := env("CONFIG_PATH", "/etc/extmcp/config.yaml")
	every, err := time.ParseDuration(env("RELOAD_INTERVAL", "5s"))
	if err != nil {
		log.Error("bad RELOAD_INTERVAL", "err", err)
		os.Exit(1)
	}
	delay, err := time.ParseDuration(env("SIMULATED_DELAY", "0s"))
	if err != nil {
		log.Error("bad SIMULATED_DELAY", "err", err)
		os.Exit(1)
	}
	store, err := policy.NewStore(path)
	if err != nil {
		log.Error("load policy", "path", path, "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go store.Watch(ctx, every, log)

	lis, err := net.Listen("tcp", ":"+env("PORT", "9001"))
	if err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	gs := grpc.NewServer()
	extmcp.RegisterExtMcpServer(gs, server.New(store, log).WithDelay(delay))
	hs := health.NewServer()
	healthpb.RegisterHealthServer(gs, hs)
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	go func() {
		<-ctx.Done()
		gs.GracefulStop()
	}()
	log.Info("extmcp listening", "addr", lis.Addr().String(), "mode", store.Get().Mode, "policy", path, "simulatedDelay", delay.String())
	if err := gs.Serve(lis); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}
