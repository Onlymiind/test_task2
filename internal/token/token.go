package token

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	algorithm = "PS512"
	tokenType = "JWT"
)

type header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type Payload struct {
	GUID     string `json:"sub"`
	IP       string `json:"ip"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
}

type TokenGenerator struct {
	accessKey       *rsa.PrivateKey
	refreshKey      *rsa.PrivateKey
	AccessDuration  time.Duration
	RefreshDuration time.Duration
}

func NewGenerator(accessDuration, refreshDuration time.Duration) (*TokenGenerator, error) {
	accessKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	accessKey.Precompute()
	refreshKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return nil, err
	}
	refreshKey.Precompute()
	return &TokenGenerator{
		accessKey:       accessKey,
		refreshKey:      refreshKey,
		AccessDuration:  accessDuration,
		RefreshDuration: refreshDuration}, nil
}

type Tokens struct {
	Access     []byte
	Refresh    []byte
	RefreshExp int64
	AccessKey  *rsa.PublicKey
	RefreshKey *rsa.PublicKey
}

type RefreshTokenInfo struct {
	Hash         []byte
	AccessKey    *rsa.PublicKey
	RefreshKey   *rsa.PublicKey
	ExpiresAfter int64
}

func (g *TokenGenerator) GenerateToken(guid, ip string) (*Tokens, error) {
	currentTime := time.Now()
	header := header{Algorithm: algorithm, Type: tokenType}
	payload := Payload{GUID: guid, IP: ip, IssuedAt: currentTime.Unix(), Expires: int64(g.AccessDuration.Seconds())}

	jsonHeader, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	accessToken := []byte{}
	accessToken = base64.URLEncoding.AppendEncode(accessToken, ([]byte)(jsonHeader))
	accessToken = append(accessToken, '.')
	accessToken = base64.URLEncoding.AppendEncode(accessToken, ([]byte)(jsonPayload))
	hash := sha512.Sum512(accessToken)
	signed, err := rsa.SignPSS(rand.Reader, g.accessKey, crypto.SHA512, hash[:], nil)
	if err != nil {
		return nil, err
	}
	accessToken = append(accessToken, '.')
	accessToken = base64.URLEncoding.AppendEncode(accessToken, signed)

	tokenHash := sha256.Sum256(accessToken)
	refreshToken, err := rsa.SignPSS(rand.Reader, g.refreshKey, crypto.SHA256, tokenHash[:], nil)
	if err != nil {
		return nil, err
	}

	return &Tokens{
		Access:     accessToken,
		Refresh:    refreshToken,
		RefreshExp: currentTime.Add(g.RefreshDuration).Unix(),
		AccessKey:  &g.accessKey.PublicKey,
		RefreshKey: &g.refreshKey.PublicKey}, nil
}

func DecodeAccessToken(token []byte) (*Payload, error) {
	parts := bytes.Split(token, []byte{'.'})
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token")
	}
	decodedJSON := []byte{}
	decodedJSON, err := base64.URLEncoding.AppendDecode(decodedJSON, parts[1])
	if err != nil {
		return nil, fmt.Errorf("non-base64 payload")
	}

	tokenPayload := Payload{}
	err = json.Unmarshal(decodedJSON, &tokenPayload)
	if err != nil {
		return nil, fmt.Errorf("invalid JSON")
	}

	return &tokenPayload, nil
}

func (g *TokenGenerator) ValidateTokenPair(access, refresh []byte, accessKey, refreshKey *rsa.PublicKey) bool {
	lastDot := strings.LastIndexByte(string(access), '.')
	if lastDot == -1 {
		return false
	}
	hashed := sha512.Sum512(access[:lastDot])
	signature, err := base64.URLEncoding.AppendDecode([]byte{}, access[lastDot+1:])
	if err != nil {
		return false
	}
	if rsa.VerifyPSS(accessKey, crypto.SHA512, hashed[:], signature, nil) != nil {
		return false
	}

	hash := sha256.Sum256(access)
	return rsa.VerifyPSS(refreshKey, crypto.SHA256, hash[:], refresh, nil) == nil
}

func GetRefreshTokenInfo(tokens *Tokens) (*RefreshTokenInfo, error) {
	result := RefreshTokenInfo{ExpiresAfter: tokens.RefreshExp, AccessKey: tokens.AccessKey, RefreshKey: tokens.RefreshKey}
	hash, err := bcrypt.GenerateFromPassword(tokens.Refresh, -1)
	if err != nil {
		return nil, err
	}
	result.Hash = hash
	return &result, err
}
