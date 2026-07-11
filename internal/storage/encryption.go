package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

const encryptedTokenPrefix = "enc:v1:"

type tokenCipher struct{ aead cipher.AEAD }

func newTokenCipher(encoded string) (*tokenCipher, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, nil
	}
	var key []byte
	var err error
	if len(encoded) == 64 {
		key, err = hex.DecodeString(encoded)
	} else {
		key, err = base64.StdEncoding.DecodeString(encoded)
	}
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("storage: CREDENTIAL_ENCRYPTION_KEY must be 64 hex characters or base64-encoded 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("storage: initialize token encryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("storage: initialize token encryption: %w", err)
	}
	return &tokenCipher{aead: aead}, nil
}

func (c *tokenCipher) encrypt(value string) (string, error) {
	if value == "" || strings.HasPrefix(value, encryptedTokenPrefix) {
		return value, nil
	}
	if c == nil {
		return value, nil
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(value), []byte(encryptedTokenPrefix))
	return encryptedTokenPrefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (c *tokenCipher) decrypt(value string) (string, error) {
	if value == "" || !strings.HasPrefix(value, encryptedTokenPrefix) {
		return value, nil
	}
	if c == nil {
		return "", fmt.Errorf("storage: encrypted credentials require CREDENTIAL_ENCRYPTION_KEY")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, encryptedTokenPrefix))
	if err != nil || len(raw) < c.aead.NonceSize() {
		return "", fmt.Errorf("storage: invalid encrypted credential")
	}
	nonce, ciphertext := raw[:c.aead.NonceSize()], raw[c.aead.NonceSize():]
	plain, err := c.aead.Open(nil, nonce, ciphertext, []byte(encryptedTokenPrefix))
	if err != nil {
		return "", fmt.Errorf("storage: credential decryption failed (wrong key or corrupt data)")
	}
	return string(plain), nil
}

func (s *Store) encryptCredential(credential Credential) (Credential, error) {
	var err error
	credential.AccessToken, err = s.cipher.encrypt(credential.AccessToken)
	if err != nil {
		return Credential{}, err
	}
	credential.RefreshToken, err = s.cipher.encrypt(credential.RefreshToken)
	return credential, err
}

func (s *Store) decryptCredential(credential Credential) (Credential, error) {
	var err error
	credential.AccessToken, err = s.cipher.decrypt(credential.AccessToken)
	if err != nil {
		return Credential{}, err
	}
	credential.RefreshToken, err = s.cipher.decrypt(credential.RefreshToken)
	return credential, err
}

func (s *Store) decryptCredentials(credentials []Credential) ([]Credential, error) {
	for i := range credentials {
		credential, err := s.decryptCredential(credentials[i])
		if err != nil {
			return nil, err
		}
		credentials[i] = credential
	}
	return credentials, nil
}
