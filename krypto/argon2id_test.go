package krypto_test

import (
	"github.com/gofac/interweb/krypto"
	"testing"
)

func TestArgon2idHashPasswordAndCheckPasswordHash(t *testing.T) {
	// Define a test password
	testPassword := "password123"

	// Hash the test password
	hashedPassword, err := krypto.Argon2idHashPassword(testPassword)
	if err != nil {
		t.Errorf("Error hashing password: %v", err)
	}
	t.Logf(hashedPassword)

}
