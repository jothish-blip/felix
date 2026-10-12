package ui

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/mattn/go-isatty"
)

// Options configures the terminal UI and progress feedback.
type Options struct {
	Writer   io.Writer
	Quiet    bool
	JSONMode bool
	NoColor  bool
}

// Progress provides non-destructive, terminal-aware progress reporting.
type Progress struct {
	mu          sync.Mutex
	writer      io.Writer
	quiet       bool
	jsonMode    bool
	interactive bool
}

// New creates a new Progress instance configured for the current terminal context.
func New(opts Options) *Progress {
	w := opts.Writer
	if w == nil {
		w = os.Stdout
	}

	interactive := false
	if f, ok := w.(*os.File); ok {
		interactive = isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
	}

	return &Progress{
		writer:      w,
		quiet:       opts.Quiet,
		jsonMode:    opts.JSONMode,
		interactive: interactive,
	}
}

// IsInteractive returns true if the output destination is an active TTY.
func (p *Progress) IsInteractive() bool {
	return p.interactive
}

// Step prints an operational step notice (e.g. "[*] Connecting to target...").
func (p *Progress) Step(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.quiet || p.jsonMode {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(p.writer, "[*] %s\n", msg)
}

// Success prints a positive observation or milestone (e.g. "[+] 12 assets discovered").
func (p *Progress) Success(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.quiet || p.jsonMode {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(p.writer, "[+] %s\n", msg)
}

// Warn prints an operational warning (e.g. "[!] Timeout reached on asset...").
func (p *Progress) Warn(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.quiet || p.jsonMode {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(p.writer, "[!] %s\n", msg)
}

// Error prints an operational error notice (e.g. "[-] Connection refused").
func (p *Progress) Error(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.quiet || p.jsonMode {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(p.writer, "[-] %s\n", msg)
}

// Callback returns a standard progress reporting function (func(string)) suitable
// for pluggable subsystems like the crawler and assessment controller.
func (p *Progress) Callback() func(string) {
	return func(msg string) {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.quiet || p.jsonMode {
			return
		}
		fmt.Fprintln(p.writer, msg)
	}
}
