package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// ServerConfig contains configuration for the HTTP server
type ServerConfig struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

// DefaultServerConfig returns the default server configuration
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Host:         "0.0.0.0",
		Port:         8080,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
}

// Server represents the HTTP server
type Server struct {
	httpServer *http.Server
	router     *Router
	logger     *slog.Logger
	config     ServerConfig
	stopCh     chan struct{}
}

// NewServer creates a new HTTP server
func NewServer(router *Router, logger *slog.Logger, config ServerConfig) (*Server, error) {
	if router == nil {
		return nil, fmt.Errorf("router is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)

	httpServer := &http.Server{
		Addr:         addr,
		Handler:      router.Handler(),
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
	}

	return &Server{
		httpServer: httpServer,
		router:     router,
		logger:     logger,
		config:     config,
		stopCh:     make(chan struct{}),
	}, nil
}

// Start starts the HTTP server
func (s *Server) Start() error {
	// Start rate limit cleanup routine
	s.router.StartRateLimitCleanup(s.stopCh)

	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	s.logger.Info("starting HTTP server", "addr", addr)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down server")

	// Signal stop to background routines
	close(s.stopCh)

	return s.httpServer.Shutdown(ctx)
}

// Address returns the server address
func (s *Server) Address() string {
	return s.httpServer.Addr
}
