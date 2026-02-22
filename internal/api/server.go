package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// ServerConfig contains configuration for the HTTP server
type ServerConfig struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`

	// TLS
	TLSEnabled    bool
	TLSCertFile   string
	TLSKeyFile    string
	TLSCAFile     string // CA cert for mTLS client verification
	TLSClientAuth bool   // Require client certificates (mTLS)
}

// DefaultServerConfig returns the default server configuration
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Host:         "127.0.0.1",
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
	if config.TLSEnabled {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS13,
		}

		// If mTLS is enabled, load CA cert and require client certificates
		if config.TLSClientAuth {
			caCert, err := os.ReadFile(config.TLSCAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA certificate: %w", err)
			}

			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA certificate")
			}

			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}

		httpServer.TLSConfig = tlsConfig
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

	if s.config.TLSEnabled {
		s.logger.Info("starting HTTPS server (TLS)", "addr", addr, "mtls", s.config.TLSClientAuth)
		return s.httpServer.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
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
