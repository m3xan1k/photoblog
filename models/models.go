package models

import "strings"

type User struct {
	Id           int
	Username     string
	PasswordHash string
}

type Photo struct {
	Id          int
	Path        string
	Description string
}

type UserPhotos struct {
	User   User
	Photos []Photo
}

func (p Photo) FilenameFromPath() string {
	splittedPath := strings.Split(p.Path, "/")
	return splittedPath[len(splittedPath)-1]
}
