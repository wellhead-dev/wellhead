package redact_test

import (
	"errors"
	"testing"

	"github.com/wellhead-dev/wellhead/internal/redact"
)

func TestMasksValuesInErrors(t *testing.T) {
	s := &redact.Set{}
	s.Add("hunter2-secret", "ab")
	err := s.Error(errors.New("server said: bad token hunter2-secret"))
	if err.Error() != "server said: bad token [redacted]" {
		t.Fatalf("got %q", err)
	}
	if s.String("ab") != redact.Mask || s.String("tab") != "tab" {
		t.Fatal("short values are masked only as whole output")
	}
}

func TestMasksTheTrimmedValueToo(t *testing.T) {
	s := &redact.Set{}
	s.Add("-----KEY-----\n")
	if s.String("got -----KEY----- back") != "got [redacted] back" {
		t.Fatal("trimmed value not masked")
	}
}

func TestKeepsErrorIdentity(t *testing.T) {
	sentinel := errors.New("not found")
	s := &redact.Set{}
	s.Add("secret-value")
	err := s.Error(errors.Join(sentinel, errors.New("secret-value")))
	if !errors.Is(err, sentinel) {
		t.Fatal("errors.Is lost")
	}
}
