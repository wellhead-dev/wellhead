// Package redact keeps secret values out of anything wellhead prints.
package redact

import (
	"errors"
	"sort"
	"strings"
	"sync"
)

// Mask replaces a secret value in output.
const Mask = "[redacted]"

// Set holds every secret value seen in a run.
type Set struct {
	mu     sync.Mutex
	values []string
}

// Add registers values to be masked. Values shorter than four bytes are masked too, but only as whole
// output, because masking a two-letter value everywhere would garble every message.
func (s *Set) Add(values ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range values {
		if v == "" {
			continue
		}
		s.values = append(s.values, v)
		if t := strings.TrimSpace(v); t != v && t != "" {
			s.values = append(s.values, t)
		}
	}
	sort.Slice(s.values, func(i, j int) bool { return len(s.values[i]) > len(s.values[j]) })
}

// String masks every registered value in text.
func (s *Set) String(text string) string {
	if s == nil {
		return text
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.values {
		if len(v) < 4 {
			if text == v {
				return Mask
			}
			continue
		}
		text = strings.ReplaceAll(text, v, Mask)
	}
	return text
}

// Error returns err with every registered value masked in its message.
func (s *Set) Error(err error) error {
	if err == nil {
		return nil
	}
	masked := s.String(err.Error())
	if masked == err.Error() {
		return err
	}
	return &redacted{msg: masked, err: err}
}

type redacted struct {
	msg string
	err error
}

func (r *redacted) Error() string { return r.msg }

func (r *redacted) Is(target error) bool { return errors.Is(r.err, target) }
