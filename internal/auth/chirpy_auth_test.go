package auth

import (
	"testing"
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
			input:    "testpass1",
			hash:     hash1,
			expected: nil,
		},
		{
			input:    "flintocks and coal stocks.",
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

// cases := []struct {
// 	input         string
// 	expectedPass  string
// 	expectedError error
// }{
// 	{
// 		input:         "testpass",
// 		expectedPass:  "someString",
// 		expectedError: nil,
// 	},
// 	{
// 		input:         nil,
// 		expectedPass:  "",
// 		expectedError: nil,
// 	},
// }

// for _, c := range cases {
// 	if

// 	for i := range actual {
// 		word := actual[i]
// 		expectedWord := c.expected[i]

// 		if expectedWord != word {
// 			t.Errorf("Expected '%s' but got '%s'.", expectedWord, word)
// 		}
// 	}
// }
