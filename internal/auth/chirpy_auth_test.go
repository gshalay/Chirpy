package auth

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	init1, init2 := "testpass1", "flintocks and coal stocks"
	actual1, err1 := HashPassword(init1)
	actual2, err2 := HashPassword(init2)

	if actual1 == init1 || actual2 == init2 {
		t.Errorf("error: couldn't hash password")
	}

	if err1 != nil {
		t.Errorf("error: %v", err1)
	}

	if err2 != nil {
		t.Errorf("error: %v", err2)
	}
}

func TestCheckPasswordHash(t *testing.T) {
	init1, init2 := "testpass1", "flintocks and coal stocks"
	hash1, _ := HashPassword(init1)
	hash2, _ := HashPassword(init2)

	cases := []struct {
		input    string
		hash     string
		expected error
	}{
		{
			input:    init1,
			hash:     hash1,
			expected: nil,
		},
		{
			input:    init2,
			hash:     hash2,
			expected: nil,
		},
	}

	for _, c := range cases {
		if c.expected != CheckPasswordHash(c.input, c.hash) {
			t.Errorf("password did not match hash")
		}
	}

	if CheckPasswordHash(init1, hash2) == nil {
		t.Errorf("hash should be invalid, but wasn't")
	}
}

func TestMakeJWT(t *testing.T) {
	cases := []struct {
		inputUUID   uuid.UUID
		inputSecret string
		expectErr   bool
	}{
		{
			inputUUID:   uuid.New(),
			inputSecret: "someSecret",
			expectErr:   false,
		},
		{
			inputUUID:   uuid.Nil,
			inputSecret: "someSecret",
			expectErr:   true,
		},
		{
			inputUUID:   uuid.New(),
			inputSecret: "",
			expectErr:   true,
		},
	}

	for _, c := range cases {
		_, err := MakeJWT(c.inputUUID, c.inputSecret, time.Hour)

		fmt.Println(err)

		if (err == nil) == c.expectErr {
			t.Errorf("error: result was not expected")
		}
	}
}

func TestValidateJWT(t *testing.T) {
	uid := uuid.New()
	s := "someSecret"
	jwt, err := MakeJWT(uid, s, time.Hour)

	if err != nil {
		t.Errorf("error: %v\n", err)
	}

	validated, err := ValidateJWT(jwt, s)

	if err != nil {
		t.Errorf("error: %v", err)
	}

	if uid != validated {
		t.Errorf("error: token invalid")
	}

}

func TestGetBearerToken(t *testing.T) {
	expected1 := "1032"
	expected2 := "1515"
	header := http.Header{}

	header.Set("Authorization", "Bearer 1032")
	actual1, err := GetBearerToken(header)
	if err != nil {
		t.Errorf("error: expected no error.")
	}

	header.Set("Authorization", "bearer 1515")
	actual2, err := GetBearerToken(header)
	if err != nil {
		t.Errorf("error: expected no error.")
	}

	header.Set("Authorization", "bearer1032")
	_, err = GetBearerToken(header)
	if err == nil {
		t.Errorf("error: expected error.")
	}

	if actual1 != expected1 || actual2 != expected2 {
		t.Errorf("error: unexpected token string.")
	}
}
