// Package client provides a Go SDK for the remote-signer service.
//
// The client SDK allows applications to interact with the remote-signer service
// for secure transaction and message signing. The key feature is the RemoteSigner
// type, which implements all ethsig signer interfaces, making it a drop-in
// replacement for local signers.
//
// # Basic Usage
//
// Create a client with Ed25519 authentication:
//
//	client, err := client.NewClient(client.Config{
//	    BaseURL:       "http://localhost:8080",
//	    APIKeyID:      "your-api-key-id",
//	    PrivateKeyHex: "your-ed25519-private-key-hex",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Using RemoteSigner
//
// Get a signer that implements all ethsig interfaces:
//
//	address := common.HexToAddress("0x1234...")
//	signer := client.GetSigner(address, "1") // chainID = 1 (Ethereum mainnet)
//
//	// Personal sign (implements ethsig.PersonalSigner)
//	sig, err := signer.PersonalSign("Hello, World!")
//
//	// Sign hash (implements ethsig.HashSigner)
//	sig, err := signer.SignHash(hash)
//
//	// Sign typed data (implements ethsig.TypedDataSigner)
//	sig, err := signer.SignTypedData(typedData)
//
//	// Sign transaction (implements ethsig.TransactionSigner)
//	signedTx, err := signer.SignTransactionWithChainID(tx, chainID)
//
// # Using with ethsig.Signer
//
// The RemoteSigner can be wrapped with ethsig.NewSigner for flexible usage:
//
//	remoteSigner := client.GetSigner(address, chainID)
//	signer := ethsig.NewSigner(remoteSigner)
//
//	// Now use all ethsig.Signer methods
//	sig, err := signer.PersonalSign("message")
//	sig, err := signer.SignTypedData(typedData)
//
// # Approval Handling
//
// By default, the Sign method waits for manual approval if required:
//
//	// This will poll until approved, rejected, or timeout
//	resp, err := client.Sign(ctx, &SignRequest{...})
//
//	// To return immediately without waiting:
//	resp, err := client.SignWithOptions(ctx, &SignRequest{...}, false)
//	if errors.Is(err, client.ErrPendingApproval) {
//	    // Handle pending approval
//	}
//
// # Configuration Options
//
//	client.Config{
//	    BaseURL:       "http://localhost:8080",  // Required
//	    APIKeyID:      "key-id",                  // Required
//	    PrivateKey:    ed25519Key,                // Either this or PrivateKeyHex
//	    PrivateKeyHex: "hex-string",              // Either this or PrivateKey
//	    HTTPClient:    customClient,              // Optional
//	    PollInterval:  2 * time.Second,           // Default: 2s
//	    PollTimeout:   5 * time.Minute,           // Default: 5m
//	}
package client
