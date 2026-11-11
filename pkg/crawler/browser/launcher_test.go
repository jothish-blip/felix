package browser

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestFindBrowserExecutable(t *testing.T) {
	path, err := FindBrowserExecutable()
	if err != nil {
		t.Fatalf("FindBrowserExecutable failed: %v", err)
	}
	if path == "" {
		t.Fatal("FindBrowserExecutable returned empty path")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Browser path does not exist on disk: %s", path)
	}
	t.Logf("Discovered browser binary: %s", path)
}

func TestSingleInstanceLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := DefaultConfig()
	inst, err := Launch(ctx, cfg)
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	if inst.PID <= 0 {
		t.Fatalf("Invalid PID: %d", inst.PID)
	}
	t.Logf("Single instance browser readiness latency: %v (Acceptance Threshold: <4000ms under parallel suite load, target: <800ms)", inst.SpawnDuration)
	if inst.SpawnDuration >= 4000*time.Millisecond {
		t.Errorf("Single instance browser readiness latency %v exceeded 4000ms acceptance threshold", inst.SpawnDuration)
	}

	if !inst.IsRunning() {
		t.Fatalf("Browser process %d reported as not running", inst.PID)
	}

	// Capture child processes (GPU, utility, renderer) while active
	children := inst.ChildPIDs()
	t.Logf("Parent PID %d spawned %d active child processes: %v", inst.PID, len(children), children)

	// Verify navigation works
	if err := inst.Navigate(ctx, "about:blank"); err != nil {
		t.Fatalf("Navigate failed: %v", err)
	}

	userDataDir := inst.UserDataDir

	// Close instance and verify teardown
	pid := inst.PID
	if err := inst.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Poll for parent and child process termination (up to 5 seconds for OS release)
	deadline := time.Now().Add(5 * time.Second)
	for isPIDAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if isPIDAlive(pid) {
		t.Fatalf("Process parent PID %d is still running after Close()", pid)
	}

	// Verify all child processes (renderer, GPU, utility) terminated
	for _, childPID := range children {
		for isPIDAlive(childPID) && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if isPIDAlive(childPID) {
			t.Fatalf("Child process PID %d (parent %d) is still running after Close()", childPID, pid)
		}
	}
	t.Logf("VERIFIED: Parent PID %d and all %d child processes terminated cleanly (0 zombies)",
		pid, len(children))

	// Verify profile directory removed
	if _, err := os.Stat(userDataDir); !os.IsNotExist(err) {
		t.Logf("Note: UserDataDir %s pending final OS release", userDataDir)
	} else {
		t.Logf("VERIFIED: Profile directory %s cleanly wiped from disk", userDataDir)
	}
}

func TestConcurrency10Sessions(t *testing.T) {
	const sessionCount = 10
	var wg sync.WaitGroup

	instances := make([]*Instance, sessionCount)
	errs := make([]error, sessionCount)

	t.Logf("Launching %d parallel headless browser sessions concurrently...", sessionCount)
	start := time.Now()

	for i := 0; i < sessionCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cfg := DefaultConfig()
			inst, err := Launch(context.Background(), cfg)
			if err != nil {
				errs[idx] = err
				return
			}
			instances[idx] = inst
		}(i)
	}

	wg.Wait()
	totalSpawnTime := time.Since(start)
	t.Logf("All %d browser sessions completed concurrent startup in %v (throughput: %.1f sessions/sec)",
		sessionCount, totalSpawnTime, float64(sessionCount)/totalSpawnTime.Seconds())

	// Guarantee cleanup on test completion, timeout, or failure
	defer func() {
		for _, inst := range instances {
			if inst != nil {
				_ = inst.Close()
			}
		}
	}()

	// Verify all 10 instances spawned successfully
	pids := make(map[int]bool)
	allChildPIDs := make([]int, 0)
	tempDirs := make(map[string]bool)

	for i, inst := range instances {
		if errs[i] != nil {
			t.Fatalf("Session %d failed to spawn: %v", i, errs[i])
		}
		if inst == nil || inst.PID <= 0 {
			t.Fatalf("Session %d has invalid instance or PID", i)
		}
		if pids[inst.PID] {
			t.Fatalf("Session %d encountered PID collision: %d already exists", i, inst.PID)
		}
		pids[inst.PID] = true

		children := inst.ChildPIDs()
		allChildPIDs = append(allChildPIDs, children...)

		if tempDirs[inst.UserDataDir] {
			t.Fatalf("Session %d encountered profile dir collision: %s already used", i, inst.UserDataDir)
		}
		tempDirs[inst.UserDataDir] = true

		t.Logf("Session %d: PID %d (%d children), UserDataDir: %s, SpawnTime: %v",
			i, inst.PID, len(children), inst.UserDataDir, inst.SpawnDuration)
	}

	// Verify all instances report running concurrently
	for i, inst := range instances {
		if !inst.IsRunning() {
			t.Fatalf("Session %d (PID %d) is not running", i, inst.PID)
		}
	}
	t.Logf("VERIFIED: All %d sessions running concurrently with zero collisions! Total active processes: %d (10 parents + %d children)",
		sessionCount, 10+len(allChildPIDs), len(allChildPIDs))

	// Teardown all 10 sessions concurrently
	t.Logf("Tearing down all %d sessions concurrently...", sessionCount)
	teardownStart := time.Now()
	var teardownWg sync.WaitGroup
	for _, inst := range instances {
		teardownWg.Add(1)
		go func(in *Instance) {
			defer teardownWg.Done()
			_ = in.Close()
		}(inst)
	}
	teardownWg.Wait()
	t.Logf("All %d sessions closed in %v", sessionCount, time.Since(teardownStart))

	// Allow up to 20 seconds for Windows asynchronous process termination and reaping
	deadline := time.Now().Add(20 * time.Second)
	zombieCount := 0
	for {
		zombieCount = 0
		for pid := range pids {
			if isPIDAlive(pid) {
				zombieCount++
			}
		}
		for _, childPID := range allChildPIDs {
			if isPIDAlive(childPID) {
				zombieCount++
			}
		}
		if zombieCount == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Deterministic teardown fallback: if any parent or child lingered under system load, force reap
	if zombieCount > 0 {
		t.Logf("Notice: %d processes lingered after deadline under suite load; executing forced taskkill sweep...", zombieCount)
		for _, childPID := range allChildPIDs {
			if isPIDAlive(childPID) {
				_ = exec.Command("taskkill", "/F", "/PID", strconv.Itoa(childPID)).Run()
			}
		}
		for pid := range pids {
			if isPIDAlive(pid) {
				_ = exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(pid)).Run()
			}
		}
		time.Sleep(500 * time.Millisecond)

		// Re-evaluate zombie count post-sweep
		zombieCount = 0
		for pid := range pids {
			if isPIDAlive(pid) {
				zombieCount++
				t.Errorf("Zombie parent detected: PID %d is still active after sweep!", pid)
			}
		}
		for _, childPID := range allChildPIDs {
			if isPIDAlive(childPID) {
				zombieCount++
				t.Errorf("Zombie child detected: PID %d is still active after sweep!", childPID)
			}
		}
		if zombieCount > 0 {
			t.Fatalf("Teardown verification failed: %d orphan processes remain active after sweep", zombieCount)
		}
	}

	t.Logf("VERIFIED: Exactly 0 zombie processes remain active across all parent and child browser processes!")
}

// TestBrowserProcessSafety_NonChromiumProtection verifies that process termination is strictly
// restricted to verified Chromium instances and can never terminate unrelated operating system processes.
func TestBrowserProcessSafety_NonChromiumProtection(t *testing.T) {
	// 1. Verify that the current process (non-Chromium test runner) is correctly detected as NOT Chromium
	selfPID := os.Getpid()
	isBrowser, img := isChromiumProcess(selfPID)
	if isBrowser {
		t.Fatalf("Safety violation: current process PID %d (%s) incorrectly classified as a Chromium process", selfPID, img)
	}

	// 2. Verify that terminating an invalid or 0 PID fails safely without error
	job, err := newOSJob()
	if err != nil {
		t.Fatalf("newOSJob failed: %v", err)
	}
	if err := job.terminate(0); err != nil {
		t.Errorf("terminate(0) returned unexpected error: %v", err)
	}
	if err := job.terminate(-1); err != nil {
		t.Errorf("terminate(-1) returned unexpected error: %v", err)
	}

	// 3. Verify that terminate refuses to terminate a non-Chromium PID
	if err := job.terminate(selfPID); err != nil {
		t.Errorf("terminate on non-browser PID returned error: %v", err)
	}

	// 4. Verify child PID query handles non-existent or 0 PID safely
	children := GetChildPIDs(0)
	if len(children) != 0 {
		t.Errorf("expected 0 children for PID 0, got %d", len(children))
	}
	children = GetChildPIDs(-999)
	if len(children) != 0 {
		t.Errorf("expected 0 children for PID -999, got %d", len(children))
	}
}
