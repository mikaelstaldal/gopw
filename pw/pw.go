// Package pw stores passwords in a file encrypted with scrypt.
//
// Requires the scrypt command line utility to be installed and available in the PATH.
package pw

import (
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"os/exec"
)

var (
	ErrPwFileNotFound      = errors.New("password file not found")
	ErrPwFileAlreadyExists = errors.New("password file already exists")
	ErrPwNotFound          = errors.New("password not found")
	ErrPwAlreadyExists     = errors.New("password already exists")
)

// PasswordEntry represents an entry in the password file.
type PasswordEntry struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Init creates a new empty password file.
func Init(filename string) error {
	if len(filename) == 0 {
		return fmt.Errorf("filename cannot be empty")
	}

	if _, err := os.Stat(filename); err == nil {
		return ErrPwFileAlreadyExists
	}

	if err := write(filename, []PasswordEntry{}); err != nil {
		return err
	}

	return nil
}

// Get fetches a password entry by name.
func Get(filename string, name string) (*PasswordEntry, error) {
	if len(filename) == 0 {
		return nil, fmt.Errorf("filename cannot be empty")
	}

	data, err := read(filename)
	if err != nil {
		return nil, err
	}

	for _, entry := range data {
		if entry.Name == name {
			return &entry, nil
		}
	}
	return nil, ErrPwNotFound
}

// List fetches all password entries.
func List(filename string) ([]PasswordEntry, error) {
	if len(filename) == 0 {
		return nil, fmt.Errorf("filename cannot be empty")
	}

	return read(filename)
}

// Add adds a new password entry.
func Add(filename string, newEntry PasswordEntry) error {
	if len(filename) == 0 {
		return fmt.Errorf("filename cannot be empty")
	}

	data, err := read(filename)
	if err != nil {
		return err
	}

	for _, entry := range data {
		if entry.Name == newEntry.Name {
			return ErrPwAlreadyExists
		}
	}

	data = append(data, newEntry)
	return write(filename, data)
}

// Update updates an existing password entry.
func Update(filename string, newEntry PasswordEntry) error {
	if len(filename) == 0 {
		return fmt.Errorf("filename cannot be empty")
	}

	data, err := read(filename)
	if err != nil {
		return err
	}

	found := false
	for i, entry := range data {
		if entry.Name == newEntry.Name {
			data[i] = newEntry
			found = true
			break
		}
	}

	if !found {
		return ErrPwNotFound
	}

	return write(filename, data)
}

// Remove removes a password entry.
func Remove(filename string, name string) error {
	if len(filename) == 0 {
		return fmt.Errorf("filename cannot be empty")
	}

	data, err := read(filename)
	if err != nil {
		return err
	}

	newData := make([]PasswordEntry, 0, len(data))
	found := false
	for _, entry := range data {
		if entry.Name != name {
			newData = append(newData, entry)
		} else {
			found = true
		}
	}

	if !found {
		return ErrPwNotFound
	}

	return write(filename, newData)
}

func read(filename string) ([]PasswordEntry, error) {
	fileMode, err := os.Stat(filename)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrPwFileNotFound
	}
	if err != nil {
		return nil, err
	}
	if fileMode.IsDir() {
		return nil, fmt.Errorf("%s is a directory", filename)
	}

	cmd := exec.Command("scrypt", "dec", filename)
	cmd.Stderr = os.Stderr
	output, err := cmd.Output()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return nil, fmt.Errorf("unable to execute scrypt dec: %w\n%s", err, string(exitErr.Stderr))
	}
	if err != nil {
		return nil, fmt.Errorf("unable to execute scrypt dec: %w", err)
	}

	var data []PasswordEntry
	if err := json.Unmarshal(output, &data); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	return data, nil
}

func write(filename string, data []PasswordEntry) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("unable to marshal to JSON: %w", err)
	}

	cmd := exec.Command("scrypt", "enc", "-", filename)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("unable to execute scrypt enc: %w", err)
	}

	if _, err := stdin.Write(jsonData); err != nil {
		_ = cmd.Cancel()
		return err
	}
	_ = stdin.Close()

	err = cmd.Wait()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return fmt.Errorf("unable to wait for scrypt enc: %w\n%s", err, string(exitErr.Stderr))
	}
	if err != nil {
		return fmt.Errorf("unable to wait for scrypt enc: %w", err)
	}

	if err := os.Chmod(filename, 0600); err != nil {
		return fmt.Errorf("unable to set filename permissions: %w", err)
	}

	return nil
}

// GeneratePassword generates a random password of length characters from the charset.
func GeneratePassword(length int, charset string) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("length must be positive")
	}

	if len(charset) == 0 {
		return "", fmt.Errorf("charset cannot be empty")
	}

	password := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		idx, err := cryptorand.Int(cryptorand.Reader, charsetLen)
		if err != nil {
			return "", err
		}
		password[i] = charset[idx.Int64()]
	}

	return string(password), nil
}
