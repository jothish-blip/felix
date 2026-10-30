package browser

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

// Common launcher errors.
var (
	ErrNoBrowserFound = errors.New("no supported headless browser executable found on system")
	ErrAlreadyClosed  = errors.New("browser instance is already closed")
)

var (
	cachedBrowserPath string
	browserPathOnce   sync.Once
	browserPathErr    error
)

// Config configures the headless browser instance lifecycle and isolation settings.
type Config struct {
	// ExecPath is the explicit path to the browser binary. If empty, FindBrowserExecutable is used.
	ExecPath string

	// Headless controls whether the browser runs without a graphical window.
	Headless bool

	// DisableGPU disables hardware GPU acceleration for reduced memory and crash avoidance.
	DisableGPU bool

	// NoSandbox disables the OS sandbox (critical for containerized CI/CD environments).
	NoSandbox bool

	// DisableDevShmUsage forces /tmp instead of /dev/shm (prevents crashes in low-memory containers).
	DisableDevShmUsage bool

	// IgnoreCertErrors allows navigation to targets with self-signed or invalid TLS certificates.
	IgnoreCertErrors bool

	// UserDataDir is the path to the isolated browser profile directory.
	// If empty, an ephemeral directory under os.TempDir() will be created automatically.
	UserDataDir string

	// AutoCleanUserDataDir determines whether the ephemeral profile directory is deleted on Close.
	AutoCleanUserDataDir bool

	// AdditionalFlags allows injecting custom Chrome DevTools command line arguments.
	AdditionalFlags map[string]any
}

// DefaultConfig returns hardened production defaults for headless security auditing.
func DefaultConfig() Config {
	return Config{
		Headless:             true,
		DisableGPU:           true,
		NoSandbox:            true,
		DisableDevShmUsage:   true,
		IgnoreCertErrors:     true,
		AutoCleanUserDataDir: true,
		AdditionalFlags:      make(map[string]any),
	}
}

// Instance represents a running headless browser session with process tree tracking.
type Instance struct {
	// PID is the OS Process ID of the browser parent process.
	PID int

	// ExecPath is the path of the executed browser binary.
	ExecPath string

	// UserDataDir is the isolated user data directory used by this session.
	UserDataDir string

	// AllocCtx is the context tied to the chromedp process allocator.
	AllocCtx context.Context

	// AllocCancel terminates the process allocator.
	AllocCancel context.CancelFunc

	// Ctx is the target context for executing browser actions.
	Ctx context.Context

	// CtxCancel terminates the browser target context.
	CtxCancel context.CancelFunc

	// SpawnDuration records the total latency required to boot and navigate to about:blank.
	SpawnDuration time.Duration

	osJob                *osJobHandle
	autoCleanUserDataDir bool
	mu                   sync.Mutex
	closed               bool
}

// FindBrowserExecutable locates Google Chrome or Microsoft Edge on the host operating system.
// Results are cached across calls to minimize filesystem stat latency.
func FindBrowserExecutable() (string, error) {
	browserPathOnce.Do(func() {
		// 1. Check environment variable overrides
		for _, envVar := range []string{"FELIX_BROWSER_PATH", "CHROME_PATH", "EDGE_PATH"} {
			if path := os.Getenv(envVar); path != "" {
				if _, err := os.Stat(path); err == nil {
					cachedBrowserPath = filepath.Clean(path)
					return
				}
			}
		}

		// 2. Platform-specific known candidate paths (Chrome prioritized for headless startup velocity)
		var candidates []string
		if runtime.GOOS == "windows" {
			candidates = []string{
				`C:\Program Files\Google\Chrome\Application\chrome.exe`,
				`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
				`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
				`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			}
		} else if runtime.GOOS == "darwin" {
			candidates = []string{
				"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
				"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
				"/Applications/Chromium.app/Contents/MacOS/Chromium",
			}
		} else {
			// Linux / BSD
			candidates = []string{
				"/usr/bin/google-chrome",
				"/usr/bin/google-chrome-stable",
				"/usr/bin/chromium",
				"/usr/bin/chromium-browser",
				"/usr/bin/microsoft-edge",
				"/usr/bin/microsoft-edge-stable",
				"/snap/bin/chromium",
			}
		}

		for _, path := range candidates {
			if _, err := os.Stat(path); err == nil {
				cachedBrowserPath = filepath.Clean(path)
				return
			}
		}

		// 3. Fallback: Search system PATH
		for _, bin := range []string{"chrome", "google-chrome", "msedge", "chromium", "microsoft-edge"} {
			if path, err := exec.LookPath(bin); err == nil {
				cachedBrowserPath = filepath.Clean(path)
				return
			}
		}

		browserPathErr = ErrNoBrowserFound
	})

	return cachedBrowserPath, browserPathErr
}

// Launch initializes and spawns an isolated headless browser process bound to a process manager.
func Launch(parentCtx context.Context, cfg Config) (*Instance, error) {
	if cfg.ExecPath == "" {
		execPath, err := FindBrowserExecutable()
		if err != nil {
			return nil, err
		}
		cfg.ExecPath = execPath
	}

	// Create ephemeral user-data-dir if not explicitly set
	userDataDir := cfg.UserDataDir
	autoClean := cfg.AutoCleanUserDataDir
	if userDataDir == "" {
		tmpDir, err := os.MkdirTemp("", "felix-browser-*")
		if err != nil {
			return nil, fmt.Errorf("failed creating temporary user-data-dir: %w", err)
		}
		userDataDir = tmpDir
		autoClean = true
	}

	// Initialize OS Job Object for clean process tree termination
	osJob, err := newOSJob()
	if err != nil {
		if autoClean {
			_ = os.RemoveAll(userDataDir)
		}
		return nil, fmt.Errorf("failed initializing OS process manager: %w", err)
	}

	// Start from DefaultExecAllocatorOptions to inherit high-performance chromium optimizations
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(cfg.ExecPath),
		chromedp.Flag("headless", cfg.Headless),
		chromedp.Flag("disable-gpu", cfg.DisableGPU),
		chromedp.Flag("no-sandbox", cfg.NoSandbox),
		chromedp.Flag("disable-dev-shm-usage", cfg.DisableDevShmUsage),
		chromedp.Flag("ignore-certificate-errors", cfg.IgnoreCertErrors),
		chromedp.Flag("user-data-dir", userDataDir),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.Flag("mute-audio", true),
		chromedp.Flag("blink-settings", "imagesEnabled=false"),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("disable-breakpad", true),
		chromedp.Flag("disable-client-side-phishing-detection", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-hang-monitor", true),
		chromedp.Flag("disable-ipc-flooding-protection", true),
		chromedp.Flag("disable-popup-blocking", true),
		chromedp.Flag("disable-prompt-on-repost", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("force-color-profile", "srgb"),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("password-store", "basic"),
		chromedp.Flag("use-mock-keychain", true),
	)

	for k, v := range cfg.AdditionalFlags {
		opts = append(opts, chromedp.Flag(k, v))
	}

	// Allocate browser process
	t0 := time.Now()
	allocCtx, allocCancel := chromedp.NewExecAllocator(parentCtx, opts...)
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)

	// Navigate to about:blank to initialize CDP connection and process loop
	if err := chromedp.Do(browserCtx, chromedp.Navigate("about:blank")); err != nil {
		browserCancel()
		allocCancel()
		_ = osJob.terminate(0)
		if autoClean {
			_ = os.RemoveAll(userDataDir)
		}
		return nil, fmt.Errorf("browser startup failed during initial handshake: %w", err)
	}
	spawnDuration := time.Since(t0)

	// Extract browser PID
	c := chromedp.FromContext(browserCtx)
	var pid int
	if c != nil && c.Browser != nil && c.Browser.Process() != nil {
		pid = c.Browser.Process().Pid
		_ = osJob.assignProcess(pid)
	}

	return &Instance{
		PID:                  pid,
		ExecPath:             cfg.ExecPath,
		UserDataDir:          userDataDir,
		AllocCtx:             allocCtx,
		AllocCancel:          allocCancel,
		Ctx:                  browserCtx,
		CtxCancel:            browserCancel,
		SpawnDuration:        spawnDuration,
		osJob:                osJob,
		autoCleanUserDataDir: autoClean,
	}, nil
}

// Close terminates the browser process tree and cleans up allocated profiles.
func (inst *Instance) Close() error {
	inst.mu.Lock()
	defer inst.mu.Unlock()

	if inst.closed {
		return nil
	}
	inst.closed = true

	// Cancel contexts
	if inst.CtxCancel != nil {
		inst.CtxCancel()
	}
	if inst.AllocCancel != nil {
		inst.AllocCancel()
	}

	// Terminate process tree via OS Job Object + taskkill fallback
	if inst.osJob != nil {
		_ = inst.osJob.terminate(inst.PID)
	}

	// Remove temporary user data directory if configured
	if inst.autoCleanUserDataDir && inst.UserDataDir != "" {
		for attempt := 0; attempt < 10; attempt++ {
			if err := os.RemoveAll(inst.UserDataDir); err == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	return nil
}

// ChildPIDs returns all active child processes spawned by this browser instance.
func (inst *Instance) ChildPIDs() []int {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	if inst.closed || inst.PID <= 0 {
		return nil
	}
	return GetChildPIDs(inst.PID)
}

// IsRunning queries the OS to verify if the browser process is currently active.
func (inst *Instance) IsRunning() bool {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	if inst.closed || inst.PID <= 0 {
		return false
	}
	return isPIDAlive(inst.PID)
}

// Navigate executes a page navigation action on the instance.
func (inst *Instance) Navigate(ctx context.Context, targetURL string) error {
	inst.mu.Lock()
	if inst.closed {
		inst.mu.Unlock()
		return ErrAlreadyClosed
	}
	inst.mu.Unlock()

	return chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL))
}
