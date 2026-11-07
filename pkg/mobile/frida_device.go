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
)

// ADBCommandRunner provides an execution interface for ADB CLI commands.
type ADBCommandRunner interface {
	Run(ctx context.Context, args ...string) ([]byte, error)
}

// SystemADBRunner executes actual adb.exe commands against the host system.
type SystemADBRunner struct {
	ADBPath string
}

func (r *SystemADBRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	if r.ADBPath == "" {
		return nil, errors.New("adb executable path not configured")
	}
	cmd := exec.CommandContext(ctx, r.ADBPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("adb error: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// ADBManager handles Android Debug Bridge device discovery and communication.
type ADBManager struct {
	Runner  ADBCommandRunner
	ADBPath string
}

// FindADBExecutable searches the environment and standard Android SDK paths for adb.exe.
func FindADBExecutable() (string, error) {
	// 1. Check PATH
	if p, err := exec.LookPath("adb"); err == nil {
		return p, nil
	}
	if p, err := exec.LookPath("adb.exe"); err == nil {
		return p, nil
	}

	// 2. Check standard Android SDK locations on Windows
	homeDir, _ := os.UserHomeDir()
	candidatePaths := []string{
		filepath.Join(homeDir, "AppData", "Local", "Android", "Sdk", "platform-tools", "adb.exe"),
		`C:\Android\Sdk\platform-tools\adb.exe`,
		`C:\Program Files (x86)\Android\android-sdk\platform-tools\adb.exe`,
	}
	for _, p := range candidatePaths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}

	return "", errors.New("adb executable not found in PATH or standard Android SDK directories")
}

// NewADBManager creates an ADBManager, automatically locating adb.exe if possible.
func NewADBManager() *ADBManager {
	adbPath, _ := FindADBExecutable()
	var runner ADBCommandRunner
	if adbPath != "" {
		runner = &SystemADBRunner{ADBPath: adbPath}
	}
	return &ADBManager{
		Runner:  runner,
		ADBPath: adbPath,
	}
}

// EnumerateDevices lists all connected devices and emulators via ADB.
func (m *ADBManager) EnumerateDevices(ctx context.Context) ([]DeviceInfo, error) {
	if m.Runner == nil {
		return nil, errors.New("adb runner unavailable")
	}

	out, err := m.Runner.Run(ctx, "devices", "-l")
	if err != nil {
		return nil, err
	}

	return ParseADBDevicesOutput(string(out)), nil
}

// ParseADBDevicesOutput parses the stdout of `adb devices -l`.
func ParseADBDevicesOutput(raw string) []DeviceInfo {
	var devices []DeviceInfo
	lines := strings.Split(raw, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "List of devices") || strings.HasPrefix(line, "*") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		serial := parts[0]
		stateStr := strings.ToLower(parts[1])

		var state DeviceState
		switch stateStr {
		case "device":
			state = DeviceStateOnline
		case "offline":
			state = DeviceStateOffline
		case "unauthorized":
			state = DeviceStateUnauthorized
		default:
			state = DeviceStateUnknown
		}

		model := extractADBTag(line, "model:")
		product := extractADBTag(line, "product:")
		deviceTag := extractADBTag(line, "device:")

		name := model
		if name == "" {
			name = deviceTag
		}
		if name == "" {
			name = serial
		}

		dType := ClassifyDeviceType(serial, product, model)

		devices = append(devices, DeviceInfo{
			ID:         serial,
			Name:       name,
			Type:       dType,
			State:      state,
			Model:      model,
			Authorized: state == DeviceStateOnline,
		})
	}

	return devices
}

func extractADBTag(line, tag string) string {
	idx := strings.Index(line, tag)
	if idx == -1 {
		return ""
	}
	sub := line[idx+len(tag):]
	end := strings.Index(sub, " ")
	if end != -1 {
		return sub[:end]
	}
	return sub
}

// ClassifyDeviceType distinguishes emulators from physical hardware.
func ClassifyDeviceType(serial, product, model string) DeviceType {
	lowerSerial := strings.ToLower(serial)
	lowerProd := strings.ToLower(product)
	lowerModel := strings.ToLower(model)

	if strings.HasPrefix(lowerSerial, "emulator-") || strings.Contains(lowerSerial, "127.0.0.1:") || strings.Contains(lowerSerial, "localhost:") {
		return DeviceTypeEmulator
	}
	if strings.Contains(lowerProd, "sdk_gphone") || strings.Contains(lowerProd, "goldfish") || strings.Contains(lowerProd, "ranchu") || strings.Contains(lowerProd, "vbox") {
		return DeviceTypeEmulator
	}
	if strings.Contains(lowerModel, "sdk") || strings.Contains(lowerModel, "emulator") || strings.Contains(lowerModel, "android sdk") {
		return DeviceTypeEmulator
	}
	if lowerSerial == "mock-device" || lowerSerial == "mock-emulator" {
		return DeviceTypeMock
	}
	return DeviceTypePhysical
}

// GetDeviceProperties queries getprop values via adb shell.
func (m *ADBManager) GetDeviceProperties(ctx context.Context, serial string) (map[string]string, error) {
	if m.Runner == nil {
		return nil, errors.New("adb runner unavailable")
	}

	out, err := m.Runner.Run(ctx, "-s", serial, "shell", "getprop")
	if err != nil {
		return nil, err
	}

	return ParseGetpropOutput(string(out)), nil
}

// ParseGetpropOutput extracts key-value pairs from `adb shell getprop`.
func ParseGetpropOutput(raw string) map[string]string {
	props := make(map[string]string)
	re := regexp.MustCompile(`\[([^\]]+)\]:\s*\[([^\]]*)\]`)
	matches := re.FindAllStringSubmatch(raw, -1)
	for _, m := range matches {
		if len(m) >= 3 {
			props[m[1]] = m[2]
		}
	}
	return props
}

// ListInstalledPackages returns all package names installed on the specified device.
func (m *ADBManager) ListInstalledPackages(ctx context.Context, serial string) ([]string, error) {
	if m.Runner == nil {
		return nil, errors.New("adb runner unavailable")
	}

	out, err := m.Runner.Run(ctx, "-s", serial, "shell", "pm", "list", "packages")
	if err != nil {
		return nil, err
	}

	return ParsePackageListOutput(string(out)), nil
}

// ParsePackageListOutput extracts package names from `pm list packages`.
func ParsePackageListOutput(raw string) []string {
	var pkgs []string
	lines := strings.Split(raw, "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "package:") {
			p := strings.TrimPrefix(l, "package:")
			if p != "" {
				pkgs = append(pkgs, p)
			}
		}
	}
	return pkgs
}
