CREATE TABLE "user_photos" (
	"id"	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	"photo_path"	TEXT NOT NULL,
	"description"	TEXT,
	"user_id"	INTEGER NOT NULL,
	FOREIGN KEY("user_id") REFERENCES "users"("id"),
	UNIQUE ("photo_path", "user_id") ON CONFLICT IGNORE
);
