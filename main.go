package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	listenPath := flag.String("listen", "/tmp/podman-proxy.sock", "Unix socket path to listen on")
	podmanSocket := flag.String("podman-socket", "/run/podman/podman.sock", "Real podman socket path")
	workspace := flag.String("workspace", "/workspace", "Allowed host path prefix for volume mounts")
	allowedImages := flag.String("allowed-images", "", "Comma-separated image allowlist (empty = allow all)")
	maxMemory := flag.Int64("max-memory", 2*1024*1024*1024, "Max memory per container in bytes")
	maxCPUs := flag.Float64("max-cpus", 2.0, "Max CPUs per container")
	agentID := flag.String("agent-id", "agent", "Agent identifier for logging/labeling")
	flag.Parse()

	// Build image allowlist.
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
	}

	proxy := &Proxy{
		PodmanSocket: *podmanSocket,
		Policy:       policy,
		Ownership:    NewOwnership(),
		AgentID:      *agentID,
	}

	// Remove stale socket file if it exists.
	os.Remove(*listenPath)

	listener, err := net.Listen("unix", *listenPath)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *listenPath, err)
	}
	// Make socket accessible to containers.
	if err := os.Chmod(*listenPath, 0666); err != nil {
		log.Printf("Warning: could not chmod socket: %v", err)
	}

	server := &http.Server{Handler: proxy}

	// Graceful shutdown on SIGTERM/SIGINT.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigCh
		log.Printf("[%s] Received %v, shutting down...", *agentID, sig)

		// Clean up owned containers before stopping.
		proxy.CleanupContainers()

		// Close the listener to stop accepting new connections.
		server.Close()
	}()

	fmt.Printf("podman-proxy [%s] listening on %s\n", *agentID, *listenPath)
	fmt.Printf("  podman socket: %s\n", *podmanSocket)
	fmt.Printf("  workspace: %s\n", *workspace)
	if len(images) > 0 {
		fmt.Printf("  allowed images: %s\n", strings.Join(images, ", "))
	}
	fmt.Printf("  max memory: %d bytes, max cpus: %.1f\n", *maxMemory, *maxCPUs)

	if err := server.Serve(listener); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}

	log.Printf("[%s] Shutdown complete.", *agentID)
}
