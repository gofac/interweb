package krypto

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
)

const (
	memory      = 4096
	iterations  = 3
	parallelism = 6
	saltLength  = 16
	keyLength   = 32
)

// Argon2idHashPassword generates an Argon2id hash from the provided password.
// It uses a cryptographically secure random salt and configurable parameters
// for iterations, memory, parallelism, and key length to generate the hash.
// The generated hash is encoded in a string format containing information about
// the hash parameters and the encoded hash itself.
//
// Parameters:
//
//	password: The plaintext password to be hashed.
//
// Returns:
//
//	string: The hashed password encoded in a string format containing hash parameters.
//	error: An error, if any, encountered during the hashing process.
func Argon2idHashPassword(password string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)
	encodedHash := base64.StdEncoding.EncodeToString(hash)
	return fmt.Sprintf("d%d$%d$%d$%s$%s", memory, iterations, parallelism, base64.StdEncoding.EncodeToString(salt), encodedHash), nil
}
