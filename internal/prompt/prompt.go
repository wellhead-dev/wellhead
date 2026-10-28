// Package prompt asks a person for values on a terminal, hidden unless asked otherwise.
package prompt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// ErrCancelled means the person ended input.
var ErrCancelled = errors.New("cancelled; nothing written")

// Prompter asks questions.
type Prompter interface {
	Secret(label string) (string, error)
	Line(label string) (string, error)
	Confirm(question string) (bool, error)
}

// Terminal prompts on a terminal: Secret reads without echo. When stdin is not a terminal it reads lines
// from it, so values can be piped in, never passed on the command line.
type Terminal struct {
	In  *os.File
	Out io.Writer
	r   *bufio.Reader
}

// NewTerminal returns a prompter on stdin and stderr.
func NewTerminal() *Terminal {
	return &Terminal{In: os.Stdin, Out: os.Stderr}
}

// Interactive reports whether stdin is a terminal.
func (t *Terminal) Interactive() bool {
	return term.IsTerminal(int(t.In.Fd())) //nolint:gosec // a file descriptor fits in an int
}

func (t *Terminal) reader() *bufio.Reader {
	if t.r == nil {
		t.r = bufio.NewReader(t.In)
	}
	return t.r
}

// Secret reads one value without echo.
func (t *Terminal) Secret(label string) (string, error) {
	_, _ = fmt.Fprintf(t.Out, "%s (hidden): ", label)
	if !t.Interactive() {
		return t.readLine()
	}
	b, err := term.ReadPassword(int(t.In.Fd())) //nolint:gosec // a file descriptor fits in an int
	_, _ = fmt.Fprintln(t.Out)
	if err != nil {
		return "", ErrCancelled
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// Line reads one value with echo.
func (t *Terminal) Line(label string) (string, error) {
	_, _ = fmt.Fprintf(t.Out, "%s: ", label)
	return t.readLine()
}

// Confirm asks a yes/no question; anything but y or yes is no.
func (t *Terminal) Confirm(question string) (bool, error) {
	_, _ = fmt.Fprintf(t.Out, "%s [y/N]: ", question)
	s, err := t.readLine()
	if err != nil {
		return false, err
	}
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "y" || s == "yes", nil
}

func (t *Terminal) readLine() (string, error) {
	s, err := t.reader().ReadString('\n')
	if err != nil && (s == "" || !errors.Is(err, io.EOF)) {
		return "", ErrCancelled
	}
	return strings.TrimRight(s, "\r\n"), nil
}
