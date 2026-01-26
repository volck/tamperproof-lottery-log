package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

var serverInitCmd = &cobra.Command{
	Use:   "server-init",
	Short: "Initialize server certificates",
	Long: `Initialize the server by generating self-signed certificates for development.
	
This command creates:
  - A Certificate Authority (CA) certificate
  - A server certificate signed by the CA
  - Private keys for both

The certificates are stored in the 'certs/' directory and are valid for 1 year.

Note: These are self-signed certificates for development only. 
In production, use certificates from a trusted CA.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		certDir := "certs"
		
		// Create certs directory if it doesn't exist
		if err := os.MkdirAll(certDir, 0755); err != nil {
			return fmt.Errorf("failed to create certs directory: %w", err)
		}

		slog.Info("Initializing server certificates", "directory", certDir)

		// Generate CA
		if err := generateCA(certDir); err != nil {
			return fmt.Errorf("failed to generate CA: %w", err)
		}

		// Generate server certificate
		if err := generateServerCert(certDir); err != nil {
			return fmt.Errorf("failed to generate server certificate: %w", err)
		}

		slog.Info("Server initialization complete!")
		slog.Info("Certificate files created:",
			"ca_cert", filepath.Join(certDir, "ca-cert.pem"),
			"server_cert", filepath.Join(certDir, "server-cert.pem"),
			"server_key", filepath.Join(certDir, "server-key.pem"),
		)
		slog.Info("You can now start the server with: lottery-tlog server")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(serverInitCmd)
}

func generateCA(certDir string) error {
	slog.Info("Generating Certificate Authority (CA)...")

	// Generate private key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create CA certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Lottery Transparency Log Dev"},
			CommonName:   "Lottery TLog CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // Valid for 1 year
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Self-sign the CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Write CA certificate
	caCertFile := filepath.Join(certDir, "ca-cert.pem")
	certOut, err := os.Create(caCertFile)
	if err != nil {
		return fmt.Errorf("failed to create CA cert file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	// Write CA private key
	caKeyFile := filepath.Join(certDir, "ca-key.pem")
	keyOut, err := os.OpenFile(caKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create CA key file: %w", err)
	}
	defer keyOut.Close()

	keyBytes, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return fmt.Errorf("failed to marshal CA private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return fmt.Errorf("failed to write CA private key: %w", err)
	}

	slog.Info("CA certificate generated", "file", caCertFile)
	return nil
}

func generateServerCert(certDir string) error {
	slog.Info("Generating server certificate...")

	// Load CA certificate and key
	caCertFile := filepath.Join(certDir, "ca-cert.pem")
	caKeyFile := filepath.Join(certDir, "ca-key.pem")

	caCertPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %w", err)
	}

	caKeyPEM, err := os.ReadFile(caKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read CA key: %w", err)
	}

	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return fmt.Errorf("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}

	caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %w", err)
	}

	// Generate server private key
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate server key: %w", err)
	}

	// Create server certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	serverTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Lottery Transparency Log Dev"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // Valid for 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Sign the server certificate with CA
	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Write server certificate
	serverCertFile := filepath.Join(certDir, "server-cert.pem")
	certOut, err := os.Create(serverCertFile)
	if err != nil {
		return fmt.Errorf("failed to create server cert file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER}); err != nil {
		return fmt.Errorf("failed to write server certificate: %w", err)
	}

	// Write server private key
	serverKeyFile := filepath.Join(certDir, "server-key.pem")
	keyOut, err := os.OpenFile(serverKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create server key file: %w", err)
	}
	defer keyOut.Close()

	keyBytes, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return fmt.Errorf("failed to marshal server private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return fmt.Errorf("failed to write server private key: %w", err)
	}

	slog.Info("Server certificate generated", "file", serverCertFile)
	return nil
}
