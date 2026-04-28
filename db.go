package main

import (
	"database/sql"
	"log"

	_ "modernc.org/sqlite"
)

func initDB() *sql.DB {
	db, err := sql.Open("sqlite", "auth.db")
	if err != nil {
		log.Fatalf("Could not open database: %v", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		username	TEXT PRIMARY KEY,
		hashed_password TEXT NOT NULL,
		session_token TEXT NOT NULL DEFAULT '',
		csrf_token TEXT NOT NULL DEFAULT ''
	)`)
	if err != nil {
		log.Fatalf("Could not create database: %v", err)
	}

	return db
}
