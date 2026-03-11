package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Logger struct {
	path string
	mu   sync.Mutex
}

type Event struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Profile   string `json:"profile,omitempty"`
	Status    string `json:"status"`
	Detail    string `json:"detail,omitempty"`
}

func New(path string) (*Logger, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir audit dir: %w", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("create audit file: %w", err)
		}
		_ = f.Close()
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("chmod audit file: %w", err)
	}
	return &Logger{path: path}, nil
}

func (l *Logger) Write(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e.Timestamp = time.Now().UTC().Format(time.RFC3339)
	e.Detail = redactSecrets(e.Detail)
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

func (l *Logger) Tail(lines int) (string, error) {
	if lines < 1 {
		lines = 1
	}
	f, err := os.Open(l.path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	buf := make([]string, 0, lines)
	for s.Scan() {
		buf = append(buf, s.Text())
		if len(buf) > lines {
			buf = buf[1:]
		}
	}
	if err := s.Err(); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = redactSecrets(buf[i])
	}
	return strings.Join(buf, "\n"), nil
}

func redactSecrets(s string) string {
	out := s
	replacer := strings.NewReplacer(
		"password", "[redacted]",
		"Password", "[redacted]",
		"passphrase", "[redacted]",
		"Passphrase", "[redacted]",
		"token", "[redacted]",
		"Token", "[redacted]",
	)
	out = replacer.Replace(out)
	if len(out) > 350 {
		out = out[:350] + "..."
	}
	return out
}
