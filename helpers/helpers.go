package helpers

import (
	"errors"
	"log"
	"net/http"

	uuid "github.com/satori/go.uuid"
)

func Check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func GetSessionCookie(req *http.Request) *http.Cookie {
	var sessionCookie *http.Cookie
	sessionCookie, err := req.Cookie("_session_id")

	if errors.Is(err, http.ErrNoCookie) {
		sessionId := uuid.NewV4().String()
		sessionCookie = &http.Cookie{
			Name:  "_session_id",
			Value: sessionId,
		}
	}
	return sessionCookie
}
