package main

import (
	"io"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"time"

	db "github.com/Onlymiind/test_task2/internal/database"
	"github.com/Onlymiind/test_task2/internal/server"
	"github.com/Onlymiind/test_task2/internal/token"
)

const (
	defaultAccessDuration  = time.Minute * 10
	defaultRefreshDuration = time.Hour * 10
)

func main() {
	var logOut io.Writer
	var err error
	logPath := os.Getenv("LOG_PATH")
	if len(logPath) != 0 {
		logOut, err = os.Open(logPath)
		if err != nil {
			log.Fatalln("failed to open log file (path: ", logPath, "): ", err.Error())
		}
	} else {
		logOut = os.Stderr
	}

	logger := log.New(logOut, "", log.LstdFlags)

	dbURL := os.Getenv("DB_URL")
	if len(dbURL) == 0 {
		logger.Fatalln("db url empty")
	}
	logger.Println(dbURL)

	db, err := db.NewDB(dbURL)
	if err != nil {
		logger.Fatalln("failed to connect to the database: ", err.Error())
	}

	var accessDuration time.Duration
	if len(os.Getenv("ACCESS_DURATION_SEC")) != 0 {
		seconds, err := strconv.ParseInt(os.Getenv("ACCESS_DURATION_SEC"), 10, 64)
		if err != nil || seconds <= 0 {
			logger.Println("invalid access token duration, setting to default")
			accessDuration = defaultAccessDuration
		} else {
			accessDuration = time.Second * time.Duration(seconds)
		}
	} else {
		accessDuration = defaultAccessDuration
	}

	var refreshDuration time.Duration
	if len(os.Getenv("REFRESH_DURATION_SEC")) != 0 {
		seconds, err := strconv.ParseInt(os.Getenv("REFRESH_DURATION_SEC"), 10, 64)
		if err != nil || seconds <= 0 {
			logger.Println("invalid refresh token duration, setting to default")
			refreshDuration = defaultRefreshDuration
		} else {
			refreshDuration = time.Second * time.Duration(seconds)
		}
	} else {
		refreshDuration = defaultRefreshDuration
	}

	generator, err := token.NewGenerator(accessDuration, refreshDuration)
	if err != nil {
		logger.Fatalln("failed to create token generator: ", err.Error())
	}

	auth := smtp.PlainAuth("", os.Getenv("EMAIL_USERNAME"), os.Getenv("EMAIL_PASSWORD"), os.Getenv("EMAIL_AUTH_HOST"))

	server := server.NewServer(db, generator, logger, auth, os.Getenv("EMAIL_SERVER_ADDRESS"), os.Getenv("EMAIL_FROM"))
	logger.Println(http.ListenAndServe(os.Getenv("SERVER_ADDRESS"), server))
}
