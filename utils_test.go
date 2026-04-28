package main

import "testing"

const password = "password123"

func TestHashPassword(t *testing.T) {
	pw, err := hashPassword(password)
	if err != nil {
		t.Errorf("the hashing function returned an error: %s", err.Error())
	}

	if len(pw) == 0 {
		t.Error("password is empty")
	}

	repeatPW, _ := hashPassword(password)
	if pw == repeatPW {
		t.Errorf("first call to hashPassword(): %s identical to repeated call: %s", pw, repeatPW)
	}
}

func TestCheckPasswordHash(t *testing.T) {
	pw, _ := hashPassword(password)
	// good password/hash combo
	if !checkPasswordHash(password, pw) {
		t.Error("checkPasswordHash did not validate the correct password")
	}

	// bad password/hash combo
	badPassword := "fish1234"
	if checkPasswordHash(badPassword, pw) {
		t.Error("checkPasswordHash validated a non-correct password")
	}
}

func TestGenerateToken(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"16 bytes", 16},
		{"32 bytes", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := generateToken(tt.length)
			if len(token) == 0 {
				t.Error("token length is zero")
			}
			repeatToken := generateToken(tt.length)
			if token == repeatToken {
				t.Error("two calls with same length produce identical tokens")
			}
		})
	}
}
