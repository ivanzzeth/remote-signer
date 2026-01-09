package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// ServerConfig contains configuration for the HTTP server
type ServerConfig struct {
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	TLS          *TLSConfig    `yaml:"tls,omitempty"`
}

// TLSConfig contains TLS configuration
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
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

	// Configure TLS if enabled
	if config.TLS != nil && config.TLS.Enabled {
		cert, err := tls.LoadX509KeyPair(config.TLS.CertFile, config.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		httpServer.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
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

	if s.config.TLS != nil && s.config.TLS.Enabled {
		s.logger.Info("starting HTTPS server", "addr", addr)
		return s.httpServer.ListenAndServeTLS("", "") // Uses TLSConfig
	}

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
