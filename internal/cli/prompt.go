package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// terminalPrompt returns a function that reads a secret from the controlling
// terminal without echo, or nil if stdin is not a terminal.
func terminalPrompt(out io.Writer) func(label string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil
	}
	return func(label string) (string, error) {
		fmt.Fprintf(out, "Enter %s: ", label)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(out)
		if err != nil {
			return "", fmt.Errorf("read from terminal: %w", err)
		}
		if len(b) == 0 {
			return "", errors.New("empty input")
		}
		return string(b), nil
	}
}
