package main

import (
	"database/sql"
	"log"

	_ "modernc.org/sqlite"
)

type Login struct {
	HashedPassword string
	SessionToken   string
	CSRFToken      string
}

type Store struct {
	db *sql.DB
}

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

// WRITES
func (s *Store) createUser(username, hashedPassword string) error {
	_, err := s.db.Exec(
		"INSERT INTO users (username, hashed_password) values (?, ?)",
		username, hashedPassword,
	)
	return err
}

func (s *Store) updateTokens(username, sessionToken, csrfToken string) error {
	_, err := s.db.Exec(
		"UPDATE users SET session_token = ?, csrf_token = ? WHERE username = ?",
		sessionToken, csrfToken, username,
	)
	return err
}

func (s *Store) clearTokens(username string) error {
	_, err := s.db.Exec(
		"UPDATE users SET session_token = '', csrf_token = '' WHERE username = ?",
		username,
	)
	return err
}

// READS
func (s *Store) getUser(username string) (Login, error) {
	var user Login
	row := s.db.QueryRow(
		"SELECT hashed_password, session_token, csrf_token FROM users WHERE username = ?",
		username)

	err := row.Scan(&user.HashedPassword, &user.SessionToken, &user.CSRFToken)
	if err != nil {
		return Login{}, err
	}

	return user, nil
}

func (s *Store) userExists(username string) bool {
	var count int
	row := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username)
	row.Scan(&count)

	return count > 0
}
