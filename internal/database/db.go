package db

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/Onlymiind/test_task2/internal/token"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	addTokenQuery    = "INSERT INTO auth_data (guid, refresh_token_hash, access_public_key, refresh_public_key, exp) VALUES($1, $2, $3, $4, $5);"
	deleteTokenQuery = "DELETE FROM auth_data WHERE guid = $1 RETURNING *;"
	getTokenQuery    = "SELECT refresh_token_hash, access_public_key, refresh_public_key, exp FROM auth_data WHERE guid = $1;"
	getEmailQuery    = "SELECT email FROM user_data WHERE guid = $1;"
)

var (
	ErrNotFound = fmt.Errorf("not found")
	ErrTooMany  = fmt.Errorf("expected a single value")
)

type DB struct {
	connectionPool *pgxpool.Pool
}

func NewDB(dbURL string) (*DB, error) {
	connection, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		return nil, err
	}

	_, err = connection.Exec(context.Background(), "CREATE TABLE IF NOT EXISTS auth_data"+
		"(guid TEXT PRIMARY KEY, refresh_token_hash TEXT NOT NULL, access_public_key TEXT NOT NULL,"+
		"refresh_public_key TEXT NOT NULL, exp BIGINT NOT NULL);")
	if err != nil {
		return nil, err
	}
	_, err = connection.Exec(context.Background(), "CREATE TABLE IF NOT EXISTS user_data(guid TEXT PRIMARY KEY, email TEXT);")
	if err != nil {
		return nil, err
	}

	return &DB{connectionPool: connection}, nil
}

func (db *DB) AddRefreshToken(guid string, info token.RefreshTokenInfo) error {
	encodedHash := base64.StdEncoding.AppendEncode([]byte{}, info.Hash)
	encodedAccessKey := base64.StdEncoding.AppendEncode([]byte{}, x509.MarshalPKCS1PublicKey(info.AccessKey))
	encodedRefreshKey := base64.StdEncoding.AppendEncode([]byte{}, x509.MarshalPKCS1PublicKey(info.RefreshKey))

	_, err := db.connectionPool.Exec(context.Background(), addTokenQuery, guid, string(encodedHash), string(encodedAccessKey), string(encodedRefreshKey), info.ExpiresAfter)
	return err
}

func (db *DB) GetRefreshTokenInfo(guid string) (*token.RefreshTokenInfo, error) {
	rows, err := db.connectionPool.Query(context.Background(), getTokenQuery, guid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, ErrNotFound
	}

	var encodedHash string
	var accessEncodedKey string
	var refreshEncodedKey string
	var expiresAfter int64
	err = rows.Scan(&encodedHash, &accessEncodedKey, &refreshEncodedKey, &expiresAfter)
	if err != nil {
		return nil, err
	}
	if rows.Next() {
		return nil, ErrTooMany
	}

	result := token.RefreshTokenInfo{ExpiresAfter: expiresAfter}
	hash, err := base64.StdEncoding.AppendDecode([]byte{}, []byte(encodedHash))
	if err != nil {
		return nil, err
	}
	result.Hash = hash

	publicKeyBytes, err := base64.StdEncoding.AppendDecode([]byte{}, ([]byte)(accessEncodedKey))
	if err != nil {
		return nil, err
	}
	result.AccessKey, err = x509.ParsePKCS1PublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}
	publicKeyBytes, err = base64.StdEncoding.AppendDecode([]byte{}, ([]byte)(refreshEncodedKey))
	if err != nil {
		return nil, err
	}
	result.RefreshKey, err = x509.ParsePKCS1PublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

func (db *DB) GetUserEmail(guid string) (string, error) {
	rows, err := db.connectionPool.Query(context.Background(), getEmailQuery, guid)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if !rows.Next() {
		return "", nil
	}
	email := ""
	err = rows.Scan(&email)
	if err != nil {
		return "", err
	}
	return email, nil
}

func (db *DB) DeleteRefreshToken(guid string) error {
	rows, err := db.connectionPool.Query(context.Background(), deleteTokenQuery, guid)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		return ErrNotFound
	}

	return nil
}
