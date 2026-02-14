package evm

import (
	"context"
	"fmt"
	"os"

	"github.com/ivanzzeth/ethsig/keystore"
)

// PasswordProvider provides passwords for keystore signers
type PasswordProvider interface {
	// GetPassword returns the password for the given keystore configuration
	GetPassword(address string, config KeystoreConfig) ([]byte, error)
}

// EnvPasswordProvider reads passwords from environment variables
type EnvPasswordProvider struct{}

// NewEnvPasswordProvider creates a new environment variable based password provider
func NewEnvPasswordProvider() (*EnvPasswordProvider, error) {
	return &EnvPasswordProvider{}, nil
}

// GetPassword reads the password from the environment variable specified in config
func (p *EnvPasswordProvider) GetPassword(address string, config KeystoreConfig) ([]byte, error) {
	if config.PasswordEnv == "" {
		return nil, fmt.Errorf("password_env not configured for keystore %s", address)
	}

	password := os.Getenv(config.PasswordEnv)
	if password == "" {
		return nil, fmt.Errorf("environment variable %s is empty for keystore %s", config.PasswordEnv, address)
	}

	return []byte(password), nil
}

// StdinPasswordProvider reads passwords from stdin interactively
type StdinPasswordProvider struct{}

// NewStdinPasswordProvider creates a new stdin-based password provider
func NewStdinPasswordProvider() (*StdinPasswordProvider, error) {
	if !keystore.IsTerminal() {
		return nil, fmt.Errorf("stdin is not a terminal, cannot use interactive password input")
	}
	return &StdinPasswordProvider{}, nil
}

// GetPassword reads the password from stdin interactively
func (p *StdinPasswordProvider) GetPassword(address string, config KeystoreConfig) ([]byte, error) {
	fmt.Printf("Enter password for keystore %s: ", address)
	password, err := keystore.ReadSecret(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to read password for %s: %w", address, err)
	}

	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty for keystore %s", address)
	}

	return password, nil
}

// CompositePasswordProvider uses stdin for password_stdin=true, env otherwise
type CompositePasswordProvider struct {
	env   *EnvPasswordProvider
	stdin *StdinPasswordProvider
}

// NewCompositePasswordProvider creates a composite password provider
// that uses stdin for keystores with password_stdin=true, otherwise uses env vars
func NewCompositePasswordProvider(hasStdinKeystores bool) (*CompositePasswordProvider, error) {
	env, err := NewEnvPasswordProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create env password provider: %w", err)
	}

	var stdin *StdinPasswordProvider
	if hasStdinKeystores {
		stdin, err = NewStdinPasswordProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdin password provider: %w", err)
		}
	}

	return &CompositePasswordProvider{
		env:   env,
		stdin: stdin,
	}, nil
}

// GetPassword returns the password using the appropriate provider based on config
func (p *CompositePasswordProvider) GetPassword(address string, config KeystoreConfig) ([]byte, error) {
	if config.PasswordStdin {
		if p.stdin == nil {
			return nil, fmt.Errorf("stdin password provider not initialized for keystore %s", address)
		}
		return p.stdin.GetPassword(address, config)
	}
	return p.env.GetPassword(address, config)
}
