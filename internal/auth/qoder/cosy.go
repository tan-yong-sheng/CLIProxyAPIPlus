// Package qoder provides authentication and API client functionality
// for Qoder AI services. It handles OAuth2 device flow authentication,
// COSY hybrid-encryption signing, and direct API calls to the Qoder cloud.
package qoder

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// RSA public key for COSY encryption (extracted from Qoder IDE v0.9)
const qoderRSAPublicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----`

// UserInfo represents the encrypted user information payload
type UserInfo struct {
	UID                string `json:"uid"`
	SecurityOAuthToken string `json:"security_oauth_token"`
	Name               string `json:"name"`
	AID                string `json:"aid"`
	Email              string `json:"email"`
}

// CosyPayload represents the payload structure for COSY authentication
type CosyPayload struct {
	Version     string `json:"version"`
	RequestID   string `json:"requestId"`
	Info        string `json:"info"`
	CosyVersion string `json:"cosyVersion"`
	IdeVersion  string `json:"ideVersion"`
}

// CosyHeaders holds the generated COSY authentication headers
type CosyHeaders struct {
	Authorization string
	CosyKey       string
	CosyUser      string
	CosyDate      string
	XRequestID    string
	XMachineOS    string
	XIDEPlatform  string
	XVersion      string
}

// Apply writes the COSY headers onto an HTTP request. Caller is responsible for
// setting Content-Type and any non-auth headers (Accept, etc.).
func (h *CosyHeaders) Apply(req *http.Request) {
	if h == nil || req == nil {
		return
	}
	req.Header.Set("Authorization", h.Authorization)
	req.Header.Set("Cosy-Key", h.CosyKey)
	req.Header.Set("Cosy-User", h.CosyUser)
	req.Header.Set("Cosy-Date", h.CosyDate)
	req.Header.Set("X-Request-Id", h.XRequestID)
	req.Header.Set("X-Machine-OS", h.XMachineOS)
	req.Header.Set("X-IDE-Platform", h.XIDEPlatform)
	req.Header.Set("X-Version", h.XVersion)
}

// parseRSAPublicKey parses the PEM-encoded RSA public key.
func parseRSAPublicKey(pemString string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, fmt.Errorf("failed to decode RSA public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}
	pubKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return pubKey, nil
}

// cosyPublicKey lazily parses qoderRSAPublicKey once and caches the result.
// The PEM bytes are a compile-time constant so the parse is deterministic;
// caching avoids repeating PEM decode + ASN.1 parse on every signed request.
var (
	cosyPublicKeyOnce sync.Once
	cosyPublicKey     *rsa.PublicKey
	cosyPublicKeyErr  error
)

func getCosyPublicKey() (*rsa.PublicKey, error) {
	cosyPublicKeyOnce.Do(func() {
		cosyPublicKey, cosyPublicKeyErr = parseRSAPublicKey(qoderRSAPublicKey)
	})
	return cosyPublicKey, cosyPublicKeyErr
}

// generateAESKey generates a random 16-character AES key (UUID hex prefix)
func generateAESKey() ([]byte, error) {
	id := uuid.New().String()
	// Remove hyphens and take first 16 characters
	hexKey := strings.ReplaceAll(id, "-", "")[:16]
	return []byte(hexKey), nil
}

// encryptUserInfo performs AES-128-CBC encryption on user info and RSA encryption on AES key
// Returns (cosyKey_b64, info_b64) where:
//   - cosyKey_b64 = base64(RSA_PKCS1_encrypt(aes_key_bytes))
//   - info_b64 = base64(AES-128-CBC_encrypt(json(user_info)))
func encryptUserInfo(userInfo *UserInfo) (string, string, error) {
	// Generate random 16-char AES key
	aesKey, err := generateAESKey()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate AES key: %w", err)
	}

	// Generate random IV for AES-CBC (should be unpredictable and unique)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", "", fmt.Errorf("failed to generate IV: %w", err)
	}

	// Serialize user info to JSON
	plaintext, err := json.Marshal(userInfo)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal user info: %w", err)
	}

	// PKCS7 padding for AES block size
	padded, err := pkcs7Pad(plaintext, aes.BlockSize)
	if err != nil {
		return "", "", fmt.Errorf("failed to pad plaintext: %w", err)
	}

	// AES-128-CBC encryption
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	// Base64 encode the encrypted info
	infoB64 := base64.StdEncoding.EncodeToString(ciphertext)

	// RSA-PKCS1-v1.5 encrypt the AES key
	pubKey, err := getCosyPublicKey()
	if err != nil {
		return "", "", err
	}

	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, aesKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt AES key: %w", err)
	}

	// Base64 encode the encrypted key
	cosyKeyB64 := base64.StdEncoding.EncodeToString(encryptedKey)

	return cosyKeyB64, infoB64, nil
}

// pkcs7Pad applies PKCS7 padding to data
func pkcs7Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 255 {
		return nil, fmt.Errorf("invalid block size: %d", blockSize)
	}

	padding := blockSize - len(data)%blockSize
	padText := bytesRepeat(byte(padding), padding)
	return append(data, padText...), nil
}

// bytesRepeat creates a byte slice with the given byte repeated count times
func bytesRepeat(b byte, count int) []byte {
	result := make([]byte, count)
	for i := range result {
		result[i] = b
	}
	return result
}

// CosyCredentials holds the per-account inputs needed to sign a COSY request.
// Build it once per call from the live token storage and pass it into
// BuildAuthHeaders.
type CosyCredentials struct {
	UserID    string
	AuthToken string
	Name      string
	Email     string
}

// FromStorage populates CosyCredentials from the persisted QoderTokenStorage.
func (c *CosyCredentials) FromStorage(s *QoderTokenStorage) {
	if c == nil || s == nil {
		return
	}
	c.UserID = s.UserID
	c.AuthToken = s.Token
	c.Name = s.Name
	c.Email = s.Email
}

// BuildAuthHeaders builds COSY v0.9 auth headers for a single signed request.
// Algorithm originates from sharedProcessMain.js (encryptUserInfo + generateAuthToken).
// CLI version and machine OS are read from the package constants.
func BuildAuthHeaders(body []byte, requestURL string, creds CosyCredentials) (*CosyHeaders, error) {
	// Build user info
	userInfo := &UserInfo{
		UID:                creds.UserID,
		SecurityOAuthToken: creds.AuthToken,
		Name:               creds.Name,
		AID:                "",
		Email:              creds.Email,
	}

	// Encrypt user info
	cosyKeyB64, infoB64, err := encryptUserInfo(userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt user info: %w", err)
	}

	// Generate request ID and timestamp
	requestID := uuid.New().String()
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	// Build payload JSON → base64
	payload := &CosyPayload{
		Version:     "v1",
		RequestID:   requestID,
		Info:        infoB64,
		CosyVersion: QoderCLIVersion,
		IdeVersion:  "",
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	payloadB64 := base64.StdEncoding.EncodeToString(payloadJSON)

	// Signing path: strip /algo prefix and query string
	parsed, err := url.Parse(requestURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request URL: %w", err)
	}
	sigPath := parsed.Path
	if strings.HasPrefix(sigPath, "/algo") {
		sigPath = sigPath[5:]
	}

	// Signature: SHA256(payload_b64 \n cosy_key \n timestamp \n body_str \n sigpath)
	bodyStr := string(body)
	sigInput := fmt.Sprintf("%s\n%s\n%s\n%s\n%s", payloadB64, cosyKeyB64, timestamp, bodyStr, sigPath)
	hash := sha256.Sum256([]byte(sigInput))
	sig := fmt.Sprintf("%x", hash)

	return &CosyHeaders{
		Authorization: fmt.Sprintf("Bearer COSY.%s.%s", payloadB64, sig),
		CosyKey:       cosyKeyB64,
		CosyUser:      creds.UserID,
		CosyDate:      timestamp,
		XRequestID:    requestID,
		XMachineOS:    QoderMachineOS,
		XIDEPlatform:  "cli",
		XVersion:      QoderCLIVersion,
	}, nil
}

// generateDeviceCodeVerifier generates a PKCE code verifier
func generateDeviceCodeVerifier() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// generateDeviceCodeChallenge creates a SHA-256 hash of the code verifier
func generateDeviceCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// generateDevicePKCEPair creates a new code verifier and its corresponding code challenge
func generateDevicePKCEPair() (string, string, error) {
	codeVerifier, err := generateDeviceCodeVerifier()
	if err != nil {
		return "", "", err
	}
	codeChallenge := generateDeviceCodeChallenge(codeVerifier)
	return codeVerifier, codeChallenge, nil
}

// generateMachineID generates a persistent machine UUID
func generateMachineID() string {
	return uuid.New().String()
}

// formatExpiresAt converts milliseconds epoch to RFC3339 format
func formatExpiresAt(expireMs int64) string {
	return time.Unix(0, expireMs*int64(time.Millisecond)).Format(time.RFC3339)
}

// parseExpiresAt parses an RFC3339 timestamp or a Unix-millisecond integer string
// into Unix milliseconds. Falls back to "now + 30 days" if the input is unparseable.
func parseExpiresAt(s string) int64 {
	s = strings.TrimSpace(s)

	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UnixMilli()
	}

	if ms, err := strconv.ParseInt(s, 10, 64); err == nil && ms > 0 {
		return ms
	}

	return time.Now().Add(30 * 24 * time.Hour).UnixMilli()
}
