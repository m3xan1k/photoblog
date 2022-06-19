package models

type User struct {
	Id           int
	Username     string
	PasswordHash string
}

type Photo struct {
	Id   int
	Path string
}

type UserPhotos struct {
	User   User
	Photos []Photo
}
