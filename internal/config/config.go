package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"fmt"
	"os"
)

// AppConfig holds the configuration settings for the OIDC server application.
type AppConfig struct {
	PublicURL  string
	KeyID      string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

// NewAppConfig creates a new AppConfig with the given public URL.
func NewAppConfig(publicUrl, keyID string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *AppConfig {
	return &AppConfig{
		PublicURL:  publicUrl,
		KeyID:      keyID,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}
}

func (c *AppConfig) GetPrivateKey() *rsa.PrivateKey {
	return c.PrivateKey
}

func (c *AppConfig) GetPublicKey() *rsa.PublicKey {
	return c.PublicKey
}

func LoadKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	f, err := LoadOrGenerateKeys("private.pem", "public.pem")
	if err != nil {
		return nil, nil, err
	}
	return f.PrivateKey, f.PublicKey, nil
}

func LoadPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM file: no PEM block found")
	}

	// PKCS#1 (traditional RSA)
	if block.Type == "RSA PRIVATE KEY" {
		key, err := ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#1 key: %w", err)
		}
		return key, nil
	}

	// PKCS#8 (modern default)
	if block.Type == "PRIVATE KEY" {
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 key: %w", err)
		}

		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key")
		}
		return key, nil
	}

	return nil, fmt.Errorf("unsupported key type: %s", block.Type)
}

func LoadPublicKeyFromFile(path string) (*rsa.PublicKey, error) {
	publicKey, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	block, _ := pem.Decode(publicKey)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid PEM file: no PUBLIC KEY block found")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return pubKey, nil
}

func LoadKeysFromFiles(privatePath, publicPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := LoadPrivateKeyFromFile(privatePath)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := LoadPublicKeyFromFile(publicPath)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

func LoadOrGenerateKeys(privatePath, publicPath string) (*KeyPair, error) {
	// Try to load existing keys
	privateKey, publicKey, err := LoadKeysFromFiles(privatePath, publicPath)
	if err == nil {
		return &KeyPair{PrivateKey: privateKey, PublicKey: publicKey}, nil
	}

	// If loading fails, generate new keys
	privateKey, publicKey, err = GenerateRSAKeys(2048)
	if err != nil {
		return nil, err
	}

	// Save the generated keys to files
	err = SaveKeysToFiles(privateKey, publicKey, privatePath, publicPath)
	if err != nil {
		return nil, err
	}

	return &KeyPair{PrivateKey: privateKey, PublicKey: publicKey}, nil
}

type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func GenerateRSAKeys(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func ParsePKCS1PrivateKey(der []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(der)
}

func SaveKeysToFiles(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, privatePath, publicPath string) error {
	// Save private key
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	err := os.WriteFile(privatePath, privPem, 0600)
	if err != nil {
		return fmt.Errorf("save private key: %w", err)
	}

	// Save public key (PKIX format)
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	err = os.WriteFile(publicPath, pubPem, 0644)
	if err != nil {
		return fmt.Errorf("save public key: %w", err)
	}

	return nil
}
