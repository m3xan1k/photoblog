package models

type User struct {
	Id           int64
	Username     string
	PasswordHash string
}

type UserSession struct {
	Id        int64
	SessionId string
	User      User
}
