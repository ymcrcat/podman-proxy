package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	listenPath := flag.String("listen", "/tmp/podman-proxy.sock", "Unix socket path to listen on")
	podmanSocket := flag.String("podman-socket", "/run/podman/podman.sock", "Real podman socket path")
	workspace := flag.String("workspace", "/workspace", "Allowed host path prefix for volume mounts")
	allowedImages := flag.String("allowed-images", "", "Comma-separated image allowlist (empty = allow all)")
	maxMemory := flag.Int64("max-memory", 2*1024*1024*1024, "Max memory per container in bytes")
	maxCPUs := flag.Float64("max-cpus", 2.0, "Max CPUs per container")
	maxPids := flag.Int64("max-pids", 1024, "Max PIDs per container (prevents fork bombs)")
	agentID := flag.String("agent-id", "agent", "Agent identifier for logging/labeling")
	flag.Parse()

	var images []string
	if *allowedImages != "" {
		for _, img := range strings.Split(*allowedImages, ",") {
			img = strings.TrimSpace(img)
			if img != "" {
				images = append(images, img)
			}
		}
	}

	policy := &Policy{
		Workspace:     *workspace,
		AllowedImages: images,
		MaxMemory:     *maxMemory,
		MaxCPUs:       *maxCPUs,
		MaxPids:       *maxPids,
	}

	proxy := &Proxy{
		PodmanSocket: *podmanSocket,
		Policy:       policy,
		Ownership:    NewOwnership(),
		AgentID:      *agentID,
		streamSem:    make(chan struct{}, maxConcurrentStream),
	}

	// Remove stale socket file if it exists.
	os.Remove(*listenPath)

	listener, err := net.Listen("unix", *listenPath)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *listenPath, err)
	}
	if err := os.Chmod(*listenPath, 0660); err != nil {
		log.Printf("Warning: could not chmod socket: %v", err)
	}

	server := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      11 * time.Minute, // slightly longer than 10-min streaming context timeout
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown on SIGTERM/SIGINT.
	// Order: stop accepting new connections, then clean up containers.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	done := make(chan struct{})
	go func() {
		sig := <-sigCh
		log.Printf("[%s] Received %v, shutting down...", *agentID, sig)

		// 1. Stop accepting new connections and drain in-flight requests.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(ctx)

		// 2. Clean up owned containers after all requests have completed.
		proxy.CleanupContainers()

		close(done)
	}()

	fmt.Printf("podman-proxy [%s] listening on %s\n", *agentID, *listenPath)
	fmt.Printf("  podman socket: %s\n", *podmanSocket)
	fmt.Printf("  workspace: %s\n", *workspace)
	if len(images) > 0 {
		fmt.Printf("  allowed images: %s\n", strings.Join(images, ", "))
	}
	fmt.Printf("  max memory: %d bytes, max cpus: %.1f, max pids: %d\n", *maxMemory, *maxCPUs, *maxPids)

	if err := server.Serve(listener); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}

	// Wait for the signal handler goroutine to finish cleanup.
	<-done

	log.Printf("[%s] Shutdown complete.", *agentID)
}
