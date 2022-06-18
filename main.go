package main

import (
	"database/sql"
	"errors"
	"html/template"
	"log"
	"net/http"
	"strings"

	sqlite3 "github.com/mattn/go-sqlite3"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

var tpl *template.Template
var db *sql.DB
var err error

type User struct {
	Id           int64
	Username     string
	PasswordHash string
}

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
	db, err = sql.Open("sqlite3", "db.sqlite3")
	check(err)
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func getSessionCookie(req *http.Request) *http.Cookie {
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

func authenticated(c *http.Cookie) bool {
	var count int
	err := db.QueryRow("SELECT Count(*) FROM sessions WHERE session_id = ?", c.Value).Scan(&count)
	check(err)

	return count == 1
}

func renderError(res http.ResponseWriter, msg string, tplName string) {
	data := struct{ Msg string }{msg}
	tpl.ExecuteTemplate(res, tplName, data)
}

func index(res http.ResponseWriter, req *http.Request) {
	tpl.ExecuteTemplate(res, "index.html", nil)
}

func signup(res http.ResponseWriter, req *http.Request) {

	sessionCookie := getSessionCookie(req)
	http.SetCookie(res, sessionCookie)
	if authenticated(sessionCookie) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	/* POST */
	if req.Method == http.MethodPost {
		/* Collect form values */
		username := strings.TrimSpace(req.FormValue("username"))
		password := strings.TrimSpace(req.FormValue("password"))
		password_repeat := strings.TrimSpace(req.FormValue("password_repeat"))

		/* Check data presence */
		if username == "" {
			renderError(res, "Username required", "signup.html")
			return
		} else if password == "" {
			renderError(res, "Password required", "signup.html")
			return
		} else if password != password_repeat {
			renderError(res, "Passwords don't match", "signup.html")
			return
		}

		/* Generate password hash */
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		check(err)

		/* Save to db */
		_, err = db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, string(passwordHash))

		/* Check unique constraint */
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) {
			if errors.Is(sqliteErr.ExtendedCode, sqlite3.ErrConstraintUnique) {
				renderError(res, "Username already taken", "signup.html")
				return
			}
		}

		/* Redirect on success */
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	/* GET */
	tpl.ExecuteTemplate(res, "signup.html", nil)
}

func login(res http.ResponseWriter, req *http.Request) {

	sessionCookie := getSessionCookie(req)
	http.SetCookie(res, sessionCookie)
	if authenticated(sessionCookie) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	/* POST */
	if req.Method == http.MethodPost {
		username := strings.TrimSpace(req.FormValue("username"))
		password := strings.TrimSpace(req.FormValue("password"))

		/* Check form values */
		if username == "" {
			renderError(res, "Username required", "login.html")
			return
		} else if password == "" {
			renderError(res, "Password required", "login.html")
			return
		}

		/* Query user with corresponding username */
		user := User{}
		row := db.QueryRow("SELECT id,username,password_hash FROM users WHERE username = ?", username)
		err = row.Scan(&user.Id, &user.Username, &user.PasswordHash)

		/* No username */
		if errors.Is(err, sql.ErrNoRows) {
			renderError(res, "Wrong username/password", "login.html")
			return
		}

		/* Wrong pass */
		err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
		if err != nil {
			renderError(res, "Wrong username/password", "login.html")
			return
		}

		/* Success */
		_, err := db.Exec(
			"INSERT INTO sessions (session_id, user_id) VALUES (?, ?)",
			sessionCookie.Value,
			user.Id,
		)
		check(err)

		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	/* GET */
	tpl.ExecuteTemplate(res, "login.html", nil)
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/login", login)
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.ListenAndServe("localhost:8000", nil)
}
