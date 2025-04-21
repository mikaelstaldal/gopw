// A command line password manager.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/atotto/clipboard"

	"github.com/mikaelstaldal/gopw/pw"
)

func main() {
	filename := flag.String("file", filepath.Join(os.Getenv("HOME"), "pw.scrypt"), "The encrypted password file")
	passwordLength := flag.Int("password-length", 16, "Password length")
	passwordChars := flag.String("password-charset", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-", "Password charset")
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		_, _ = fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		_, _ = fmt.Fprintln(os.Stderr)
		_, _ = fmt.Fprintf(os.Stderr, `Commands:
  init      Create an empty encrypted passwords file
  get       Lookup a password
  list      List all passwords
  add       Add a password
  update    Update a password
  remove    Remove a password
  generate  Generates a password without storing it
`)
		_, _ = fmt.Fprintln(os.Stderr)
		_, _ = fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
		os.Exit(1)
	}
	command := args[0]

	switch command {
	case "init":
		initCmd(*filename)

	case "get":
		if len(args) < 2 {
			_, _ = fmt.Fprintln(os.Stderr, "Name required")
			os.Exit(1)
		}
		getCmd(*filename, args[1])

	case "list":
		listCmd(*filename)

	case "add":
		if len(args) < 3 {
			_, _ = fmt.Fprintln(os.Stderr, "Name and username required")
			os.Exit(1)
		}
		addCmd(*passwordLength, *passwordChars, *filename, args[1], args[2])

	case "update":
		if len(args) < 3 {
			_, _ = fmt.Fprintln(os.Stderr, "Name and username required")
			os.Exit(1)
		}
		updateCmd(*passwordLength, *passwordChars, *filename, args[1], args[2])

	case "remove":
		if len(args) < 2 {
			_, _ = fmt.Fprintln(os.Stderr, "Name required")
			os.Exit(1)
		}
		removeCmd(*filename, args[1])

	case "generate":
		generateCmd(*passwordLength, *passwordChars)

	default:
		fmt.Printf("Unknown command: %s\n", command)
		os.Exit(1)
	}
}

func initCmd(filename string) {
	if err := pw.Init(filename); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s initialized\n", filename)
}

func getCmd(filename string, name string) {
	entry, err := pw.Get(filename, name)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if entry.Username != "" {
		fmt.Println(entry.Username)
	}
	if err = clipboard.WriteAll(entry.Password); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: unable to access clipboard: %v\n", err)
		os.Exit(1)
	}
}

func listCmd(filename string) {
	entries, err := pw.List(filename)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	for _, entry := range entries {
		fmt.Printf("%s: %s\n", entry.Name, entry.Username)
	}
}

func addCmd(passwordLength int, passwordChars string, filename string, name string, username string) {
	password, err := pw.GeneratePassword(passwordLength, passwordChars)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	err = pw.Add(filename, pw.PasswordEntry{
		Name:     name,
		Username: username,
		Password: password,
	})
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if err = clipboard.WriteAll(password); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: unable to access clipboard: %v\n", err)
		os.Exit(1)
	}
}

func updateCmd(passwordLength int, passwordChars string, filename string, name string, username string) {
	password, err := pw.GeneratePassword(passwordLength, passwordChars)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	err = pw.Update(filename, pw.PasswordEntry{
		Name:     name,
		Username: username,
		Password: password,
	})
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if err = clipboard.WriteAll(password); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: unable to access clipboard: %v\n", err)
		os.Exit(1)
	}
}

func removeCmd(filename string, name string) {
	if err := pw.Remove(filename, name); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func generateCmd(passwordLength int, passwordChars string) {
	password, err := pw.GeneratePassword(passwordLength, passwordChars)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if err = clipboard.WriteAll(password); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: unable to access clipboard: %v\n", err)
		os.Exit(1)
	}
}
