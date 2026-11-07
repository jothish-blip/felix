package mobile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// FridaInfo holds detection results for the host Frida installation.
type FridaInfo struct {
	Available             bool   `json:"available"`
	Version               string `json:"version"`
	BinaryPath            string `json:"binary_path,omitempty"`
	PythonModuleAvailable bool   `json:"python_module_available"`
	PythonModuleVersion   string `json:"python_module_version,omitempty"`
	Error                 string `json:"error,omitempty"`
}

// FridaManager orchestrates Frida runtime detection, device management, and session creation.
type FridaManager struct {
	ADB          *ADBManager
	FridaPath    string
	PythonPath   string
	MockDevice   *DeviceInfo
	MockMessages []string
}

// NewFridaManager initializes a manager with automated environment discovery.
func NewFridaManager() *FridaManager {
	return &FridaManager{
		ADB: NewADBManager(),
	}
}

// FindFridaBinary searches PATH, environment variables, and standard Python script directories.
func FindFridaBinary() (string, error) {
	if custom := os.Getenv("FRIDA_PATH"); custom != "" {
		if fi, err := os.Stat(custom); err == nil && !fi.IsDir() {
			return custom, nil
		}
	}

	if p, err := exec.LookPath("frida"); err == nil {
		return p, nil
	}
	if p, err := exec.LookPath("frida.exe"); err == nil {
		return p, nil
	}

	// Check standard Windows Python Scripts directories
	homeDir, _ := os.UserHomeDir()
	candidatePaths := []string{
		filepath.Join(homeDir, "AppData", "Local", "Programs", "Python", "Python311", "Scripts", "frida.exe"),
		filepath.Join(homeDir, "AppData", "Local", "Programs", "Python", "Python312", "Scripts", "frida.exe"),
		filepath.Join(homeDir, "AppData", "Local", "Programs", "Python", "Python310", "Scripts", "frida.exe"),
		`C:\Program Files\Python311\Scripts\frida.exe`,
		`C:\Python311\Scripts\frida.exe`,
	}

	for _, p := range candidatePaths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}

	return "", errors.New("frida binary not located in PATH or Python Scripts directories")
}

// ParseFridaVersion parses semantic version strings from `frida --version`.
func ParseFridaVersion(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	re := regexp.MustCompile(`(\d+\.\d+\.\d+)`)
	m := re.FindStringSubmatch(raw)
	if len(m) >= 2 {
		return m[1], nil
	}
	return "", fmt.Errorf("unable to parse semantic version from: %q", raw)
}

// DetectFrida evaluates Frida binary and Python module availability on the host.
func (m *FridaManager) DetectFrida() (*FridaInfo, error) {
	info := &FridaInfo{
		Available: false,
	}

	// 1. Detect binary
	binPath, err := FindFridaBinary()
	if err == nil {
		m.FridaPath = binPath
		info.BinaryPath = binPath
		cmd := exec.Command(binPath, "--version")
		out, verErr := cmd.Output()
		if verErr == nil {
			v, pErr := ParseFridaVersion(string(out))
			if pErr == nil {
				info.Available = true
				info.Version = v
			}
		}
	}

	// 2. Detect Python module
	pyCmd := exec.Command("python", "-c", "import frida; print(frida.__version__)")
	pyOut, pyErr := pyCmd.Output()
	if pyErr == nil {
		v, pErr := ParseFridaVersion(string(pyOut))
		if pErr == nil {
			info.PythonModuleAvailable = true
			info.PythonModuleVersion = v
			if !info.Available {
				info.Available = true
				info.Version = v
			}
		}
	}

	if !info.Available {
		info.Error = "Frida runtime not detected on host system"
		return info, errors.New(info.Error)
	}

	return info, nil
}

// EnumerateDevices lists all connected devices via ADB and checks for mock devices.
func (m *FridaManager) EnumerateDevices(ctx context.Context) ([]DeviceInfo, error) {
	var devices []DeviceInfo

	if m.MockDevice != nil {
		devices = append(devices, *m.MockDevice)
	}

	if m.ADB != nil {
		adbDevs, err := m.ADB.EnumerateDevices(ctx)
		if err == nil {
			devices = append(devices, adbDevs...)
		}
	}

	return devices, nil
}

// GetDevice returns metadata for a specific device ID.
func (m *FridaManager) GetDevice(ctx context.Context, id string) (*DeviceInfo, error) {
	devs, err := m.EnumerateDevices(ctx)
	if err != nil {
		return nil, err
	}

	for _, d := range devs {
		if d.ID == id {
			return &d, nil
		}
	}

	return nil, fmt.Errorf("device %q not found", id)
}

// ValidateTargetPackage checks if a package is authorized by the laboratory allowlist.
func (m *FridaManager) ValidateTargetPackage(pkg string) error {
	return ValidateLaboratoryPackage(pkg)
}

// CreateSession establishes an instrumentation session for an authorized package.
func (m *FridaManager) CreateSession(ctx context.Context, cfg SessionConfig) (DynamicSession, error) {
	if err := m.ValidateTargetPackage(cfg.TargetPackage); err != nil {
		return nil, err
	}

	var dev DeviceInfo
	if cfg.DeviceID != "" {
		d, err := m.GetDevice(ctx, cfg.DeviceID)
		if err != nil {
			return nil, err
		}
		dev = *d
	} else {
		devs, err := m.EnumerateDevices(ctx)
		if err != nil || len(devs) == 0 {
			// Check if host Frida is present; if so, default to local/headless info
			dev = DeviceInfo{
				ID:         "local",
				Name:       "Local System",
				Type:       DeviceTypePhysical,
				State:      DeviceStateOnline,
				Authorized: true,
			}
		} else {
			dev = devs[0]
		}
	}

	sess := NewFridaSession(cfg, dev)

	// If mock messages are provided for testing, load them into session
	if len(m.MockMessages) > 0 {
		go func() {
			time.Sleep(5 * time.Millisecond)
			for _, msg := range m.MockMessages {
				_ = sess.ProcessJSONMessage(msg)
			}
		}()
	}

	return sess, nil
}

// ExecutePythonScript executes a controlled Python helper script that communicates with Frida.
func (m *FridaManager) ExecutePythonScript(ctx context.Context, scriptContent string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "python", "-c", scriptContent)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("python frida error: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
