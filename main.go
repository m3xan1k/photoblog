package main

import (
	"database/sql"
	"errors"
	"html/template"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/m3xan1k/netservers/photoblog/helpers"
	"github.com/m3xan1k/netservers/photoblog/models"
	sqlite3 "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

const (
	photosRoot = "static"
)

var tpl *template.Template
var db *sql.DB
var err error

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
	db, err = sql.Open("sqlite3", "db.sqlite3")
	helpers.Check(err)
}

func authenticated(c *http.Cookie) bool {
	var count int
	err := db.QueryRow(
		"SELECT Count(*) FROM user_sessions WHERE session_id = ?", c.Value,
	).Scan(&count)
	helpers.Check(err)

	return count == 1
}

func getCurrentUser(c *http.Cookie) models.User {
	user := models.User{}
	row := db.QueryRow(
		`SELECT users.id,users.username
		FROM user_sessions
		INNER JOIN users
		ON user_sessions.user_id = users.id
		WHERE user_sessions.session_id = ?`,
		c.Value,
	)
	err = row.Scan(&user.Id, &user.Username)
	helpers.Check(err)
	return user
}

func renderError(res http.ResponseWriter, msg string, tplName string) {
	data := struct{ Msg string }{msg}
	tpl.ExecuteTemplate(res, tplName, data)
}

func index(res http.ResponseWriter, req *http.Request) {

	sessionCookie := helpers.GetSessionCookie(req)
	http.SetCookie(res, sessionCookie)

	user := models.User{}
	if authenticated(sessionCookie) {
		user = getCurrentUser(sessionCookie)
	}
	tpl.ExecuteTemplate(res, "index.html", user)
}

func signup(res http.ResponseWriter, req *http.Request) {

	sessionCookie := helpers.GetSessionCookie(req)
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
		helpers.Check(err)

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

	sessionCookie := helpers.GetSessionCookie(req)
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
		user := models.User{}
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
			"INSERT INTO user_sessions (session_id, user_id) VALUES (?, ?)",
			sessionCookie.Value,
			user.Id,
		)
		helpers.Check(err)

		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	/* GET */
	tpl.ExecuteTemplate(res, "login.html", nil)
}

func logout(res http.ResponseWriter, req *http.Request) {
	sessionCookie := helpers.GetSessionCookie(req)

	/* Remove user's session from DB */
	db.Exec("DELETE FROM user_sessions WHERE session_id = ?", sessionCookie.Value)

	/* Remove session cookie from client */
	sessionCookie.MaxAge = -1
	http.SetCookie(res, sessionCookie)

	http.Redirect(res, req, "/", http.StatusSeeOther)
}

func upload(res http.ResponseWriter, req *http.Request) {
	sessionCookie := helpers.GetSessionCookie(req)
	http.SetCookie(res, sessionCookie)
	if !authenticated(sessionCookie) {
		http.Redirect(res, req, "/login", http.StatusSeeOther)
		return
	}

	/* Get current user */
	user := getCurrentUser(sessionCookie)

	/* POST */
	if req.Method == http.MethodPost {
		/* Check or Create user's photo dir */
		dirname := path.Join(photosRoot, user.Username)
		err = os.MkdirAll(dirname, 0755)
		if !errors.Is(err, os.ErrExist) {
			helpers.Check(err)
		}

		/* Get file stream from form */
		iFile, fileHeader, err := req.FormFile("photo")
		helpers.Check(err)
		defer iFile.Close()

		/* Create output file stream */
		oFilePath := filepath.Join(
			dirname,
			strings.Trim(fileHeader.Filename, " "),
		)
		oFile, err := os.OpenFile(oFilePath, os.O_WRONLY|os.O_CREATE, 0755)
		helpers.Check(err)
		defer iFile.Close()

		/* Save file */
		io.Copy(oFile, iFile)

		/* Photo description */
		photoDescription := req.FormValue("description")

		/* Save to DB */
		var sqliteErr sqlite3.Error
		_, err = db.Exec(
			"INSERT INTO user_photos (photo_path, description, user_id) VALUES (?, ?, ?)",
			oFilePath,
			photoDescription,
			user.Id,
		)
		if errors.As(err, &sqliteErr) {
			if errors.Is(sqliteErr.ExtendedCode, sqlite3.ErrConstraintUnique) {
				renderError(res, "File already exists", "upload.html")
				return
			}
		}

		http.Redirect(res, req, "/photos", http.StatusSeeOther)
		return
	}

	/* GET */
	tpl.ExecuteTemplate(res, "upload.html", nil)
}

func photos(res http.ResponseWriter, req *http.Request) {
	sessionCookie := helpers.GetSessionCookie(req)
	http.SetCookie(res, sessionCookie)
	if !authenticated(sessionCookie) {
		http.Redirect(res, req, "/login", http.StatusSeeOther)
		return
	}

	/* Get current user */
	user := getCurrentUser(sessionCookie)

	/* Query user's photos */
	rows, err := db.Query(
		`SELECT up.id,up.photo_path,up.description
		FROM user_photos as up
		INNER JOIN users
		ON up.user_id = users.id
		WHERE users.id = ?`,
		user.Id,
	)
	if !errors.Is(err, sql.ErrNoRows) {
		helpers.Check(err)
	}

	/* Append photos to struct field */
	uPhotos := models.UserPhotos{User: user}
	for rows.Next() {
		photo := models.Photo{}
		err = rows.Scan(&photo.Id, &photo.Path, &photo.Description)
		helpers.Check(err)

		uPhotos.Photos = append(uPhotos.Photos, photo)
	}

	tpl.ExecuteTemplate(res, "photos.html", uPhotos)
}

func photo(res http.ResponseWriter, req *http.Request) {
	sessionCookie := helpers.GetSessionCookie(req)
	http.SetCookie(res, sessionCookie)
	if !authenticated(sessionCookie) {
		http.Redirect(res, req, "/login", http.StatusSeeOther)
		return
	}

	/* Get current user */
	user := getCurrentUser(sessionCookie)

	photoId := req.FormValue("id")

	/* Query photo */
	var photoUserId int
	photo := models.Photo{}
	row := db.QueryRow(
		"SELECT id,photo_path,description,user_id FROM user_photos WHERE id = ?",
		photoId,
	)
	err = row.Scan(&photo.Id, &photo.Path, &photo.Description, &photoUserId)
	if !errors.Is(err, sql.ErrNoRows) {
		helpers.Check(err)
	}

	// TODO: private and public photos
	/* Check photo owner */
	if user.Id != photoUserId {
		http.Redirect(res, req, "/", http.StatusSeeOther)
	}

	tpl.ExecuteTemplate(res, "photo.html", photo)
}

func deletePhoto(res http.ResponseWriter, req *http.Request) {
	sessionCookie := helpers.GetSessionCookie(req)
	http.SetCookie(res, sessionCookie)
	if !authenticated(sessionCookie) {
		http.Redirect(res, req, "/login", http.StatusSeeOther)
		return
	}

	/* Get current user */
	user := getCurrentUser(sessionCookie)

	photoId := req.FormValue("id")

	/* Delete record that matches both id and user_id */
	db.Exec("DELETE FROM user_photos WHERE user_id = ? AND id = ?", user.Id, photoId)
	http.Redirect(res, req, "/photos", http.StatusSeeOther)
}

func main() {
	fs := http.FileServer(http.Dir(photosRoot))
	http.Handle("/static/", http.StripPrefix("/static", fs))
	http.HandleFunc("/", index)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/upload", upload)
	http.HandleFunc("/photos", photos)
	http.HandleFunc("/photo", photo)
	http.HandleFunc("/delete_photo", deletePhoto)
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.ListenAndServe("localhost:8000", nil)
}
