package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	db "github.com/Onlymiind/test_task2/internal/database"
	"github.com/Onlymiind/test_task2/internal/token"
	"golang.org/x/crypto/bcrypt"
)

const (
	authPath              = "/auth"
	refreshPath           = "/refresh"
	authHeader            = "Authorization"
	bearerPrefix          = "Bearer"
	guidParameter         = "guid"
	refreshTokenParameter = "refresh"
	whitespace            = " \t\r\n"
)

type Server struct {
	db                 *db.DB
	tokenGenerator     *token.TokenGenerator
	logger             *log.Logger
	emailAuth          smtp.Auth
	emailFrom          string
	emailServerAddress string
}

type tokenInfo struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in"`
}

type tokensResponse struct {
	Access  tokenInfo `json:"access"`
	Refresh tokenInfo `json:"refresh"`
}

func NewServer(db *db.DB, tokenGenerator *token.TokenGenerator, logger *log.Logger, emailAuth smtp.Auth, emailServerAddress, emailFrom string) *Server {
	return &Server{
		db:                 db,
		logger:             logger,
		emailAuth:          emailAuth,
		emailServerAddress: emailServerAddress,
		emailFrom:          emailFrom,
		tokenGenerator:     tokenGenerator,
	}
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case authPath:
		s.serveGenerateTokens(writer, request)
	case refreshPath:
		s.serveRefresh(writer, request)
	default:
		writer.WriteHeader(http.StatusBadRequest)
		s.logger.Println("path not found: ", request.URL.Path)
	}
}

func (s *Server) serveGenerateTokens(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write(([]byte)("only POST requests are allowed"))
		return
	}

	ip, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		s.logger.Println("failed to parse ip")
		return
	}

	guid, err := getURLEncodedFromBody(guidParameter, request)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		s.logger.Println("failed to get guid: ", err.Error())
		return
	}

	s.generateTokens(guid, ip, writer)
}

func (s *Server) serveRefresh(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write(([]byte)("only POST requests are allowed"))
		return
	}

	if len(request.Header[authHeader]) == 0 {
		writer.WriteHeader(http.StatusUnauthorized)
		s.logger.Println("Missing ", authHeader, " header in refresh request")
		return
	}
	accessToken, found := strings.CutPrefix(strings.Trim(request.Header[authHeader][0], whitespace), bearerPrefix)
	if !found {
		writer.WriteHeader(http.StatusUnauthorized)
		s.logger.Println("invalid or empty ", authHeader, " header in refresh request")
		return
	}
	accessToken = strings.Trim(accessToken, whitespace)
	if len(accessToken) == 0 {
		writer.WriteHeader(http.StatusUnauthorized)
		s.logger.Println("invalid or empty ", authHeader, " header in refresh request")
		return
	}
	encodedRefreshToken, err := getURLEncodedFromBody(refreshTokenParameter, request)
	if err != nil {
		writer.WriteHeader(http.StatusUnauthorized)
		s.logger.Println("failed to get refresh token: ", err.Error())
		return
	}
	refreshToken := []byte{}
	refreshToken, err = base64.URLEncoding.AppendDecode(refreshToken, []byte(encodedRefreshToken))
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		s.logger.Println("failed to decode refresh token: ", err.Error())
		return
	}

	payload, err := token.DecodeAccessToken([]byte(accessToken))
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		s.logger.Println("failed to decode access token: ", err.Error())
		return
	}
	refreshInfo, err := s.db.GetRefreshTokenInfo(payload.GUID)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		s.logger.Println("failed to retrieve refresh token data: ", err.Error())
		return
	}
	err = bcrypt.CompareHashAndPassword(refreshInfo.Hash, refreshToken)
	if err != nil {
		writer.WriteHeader(http.StatusUnauthorized)
		s.logger.Println("provided refresh token does not match the hash", err.Error())
		return
	}

	if !s.tokenGenerator.ValidateTokenPair([]byte(accessToken), []byte(refreshToken), refreshInfo.AccessKey, refreshInfo.RefreshKey) {
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write(([]byte)("invalid token"))
		return
	}
	if time.Now().Compare(time.Unix(refreshInfo.ExpiresAfter, 0)) > 0 {
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write(([]byte)("token expired"))
		return
	}

	ip, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		s.logger.Println("failed to parse ip: ", err.Error())
		return
	}

	if ip != payload.IP {
		email, err := s.db.GetUserEmail(payload.GUID)
		if err != nil {
			s.logger.Println("failed to retrieve user email: ", err.Error())
		} else if len(email) != 0 && len(s.emailServerAddress) != 0 && len(s.emailFrom) != 0 {
			err = smtp.SendMail(s.emailServerAddress, s.emailAuth, s.emailFrom, []string{email}, []byte(
				"To: "+email+"\r\n"+
					"From: "+s.emailFrom+"\r\n"+
					"Subject: Auth warning\r\n"+
					"Warning! Someone refreshed access!\r\n"))
			if err != nil {
				s.logger.Println("failed to send email warning: ", err.Error())
			}
		}
	}

	err = s.db.DeleteRefreshToken(payload.GUID)
	if err == db.ErrNotFound {
		//Token was deleted by a concurrent refresh operation
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write(([]byte)("invalid token"))
		return
	} else if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		s.logger.Println("failed to delete old token: ", err.Error())
		return
	}

	s.generateTokens(payload.GUID, ip, writer)
}

func (s *Server) generateTokens(guid, ip string, writer http.ResponseWriter) {
	tokens, err := s.tokenGenerator.GenerateToken(guid, ip)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		s.logger.Println("failed to generate tokens: ", err.Error())
		return
	}

	encodedRefresh := []byte{}
	encodedRefresh = base64.URLEncoding.AppendEncode(encodedRefresh, tokens.Refresh)
	response := tokensResponse{
		Access:  tokenInfo{Token: string(tokens.Access), ExpiresIn: int64(s.tokenGenerator.AccessDuration.Seconds())},
		Refresh: tokenInfo{Token: string(encodedRefresh), ExpiresIn: int64(s.tokenGenerator.RefreshDuration.Seconds())},
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		s.logger.Println("failed to JSON-encode response: ", err.Error())
		return
	}

	refreshInfo, err := token.GetRefreshTokenInfo(tokens)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		s.logger.Println("failed to get bcrypt hash: ", err.Error())
		return
	}

	err = s.db.AddRefreshToken(guid, *refreshInfo)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		s.logger.Println("failed to save token to database: ", err.Error())
		return
	}

	writer.Header().Add("Content-Type", "application/json")
	writer.Write(responseBytes)
}

func getURLEncodedFromBody(key string, request *http.Request) (string, error) {
	if request.ContentLength == 0 {
		return "", fmt.Errorf("empty request, expected '%s' parameter in the body", key)
	}
	body := make([]byte, request.ContentLength)
	_, err := request.Body.Read(body)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("failed to read request's body: %s", err.Error())
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", fmt.Errorf("failed to parse parameters: %s", err.Error())
	} else if len(values[key]) == 0 || len(values[key][0]) == 0 {
		return "", fmt.Errorf("no parameter '%s' in request's body", key)
	}
	return values[key][0], nil
}
