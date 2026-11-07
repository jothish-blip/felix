package mobile

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// FridaSession implements DynamicSession to control and observe a target application process.
type FridaSession struct {
	Config      SessionConfig
	Device      DeviceInfo
	StateVal    SessionState
	EventsChan  chan RuntimeEvent
	Collected   []RuntimeEvent
	Errors      []string
	StartedAt   time.Time
	CompletedAt time.Time

	mu          sync.RWMutex
	cancelFunc  context.CancelFunc
	cmd         *exec.Cmd
	stdin       io.WriteCloser
	droppedEvts uint64
	doneChan    chan struct{}
}

// NewFridaSession initializes a session instance in CREATED state.
func NewFridaSession(cfg SessionConfig, dev DeviceInfo) *FridaSession {
	bufCap := cfg.MaxEvents
	if bufCap <= 0 || bufCap > 5000 {
		bufCap = 1000
	}

	return &FridaSession{
		Config:     cfg,
		Device:     dev,
		StateVal:   SessionStateCreated,
		EventsChan: make(chan RuntimeEvent, bufCap),
		Collected:  make([]RuntimeEvent, 0),
		Errors:     make([]string, 0),
		doneChan:   make(chan struct{}),
	}
}

// State returns the current session state in a thread-safe manner.
func (s *FridaSession) State() SessionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.StateVal
}

// Events returns the receive-only channel of runtime events.
func (s *FridaSession) Events() <-chan RuntimeEvent {
	return s.EventsChan
}

// setState transitions session state under lock.
func (s *FridaSession) setState(st SessionState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.StateVal = st
}

// Start begins instrumentation, either by spawning or attaching to the target process.
func (s *FridaSession) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.StateVal != SessionStateCreated {
		s.mu.Unlock()
		return fmt.Errorf("cannot start session in state %s", s.StateVal)
	}

	if err := ValidateLaboratoryPackage(s.Config.TargetPackage); err != nil {
		s.StateVal = SessionStateFailed
		s.mu.Unlock()
		return err
	}

	sessCtx, cancel := context.WithTimeout(ctx, s.Config.Timeout)
	s.cancelFunc = cancel
	s.StartedAt = time.Now().UTC()
	s.StateVal = SessionStateAttaching
	s.mu.Unlock()

	// In real execution, Frida CLI or Python runner is launched here.
	// For headless/unit execution or when cmd is not pre-set, session enters RUNNING.
	s.setState(SessionStateRunning)

	go func() {
		<-sessCtx.Done()
		if sessCtx.Err() == context.DeadlineExceeded {
			s.mu.Lock()
			s.Errors = append(s.Errors, "session reached configured execution timeout")
			s.mu.Unlock()
		}
		_ = s.Stop()
	}()

	return nil
}

// Stop cleanly terminates the instrumentation session and flushes pending events.
func (s *FridaSession) Stop() error {
	s.mu.Lock()
	if s.StateVal == SessionStateTerminated || s.StateVal == SessionStateFailed {
		s.mu.Unlock()
		return nil
	}
	s.StateVal = SessionStateDetaching

	if s.cancelFunc != nil {
		s.cancelFunc()
	}

	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}

	s.CompletedAt = time.Now().UTC()
	s.StateVal = SessionStateTerminated
	close(s.doneChan)
	close(s.EventsChan)
	s.mu.Unlock()

	return nil
}

// ProcessJSONMessage decodes and validates a raw Frida IPC message string.
func (s *FridaSession) ProcessJSONMessage(raw string) error {
	var genericMsg map[string]any
	if err := json.Unmarshal([]byte(raw), &genericMsg); err != nil {
		s.mu.Lock()
		s.Errors = append(s.Errors, fmt.Sprintf("malformed JSON from Frida: %v", err))
		s.mu.Unlock()
		return fmt.Errorf("malformed JSON: %w", err)
	}

	// Frida message formats:
	// 1. Direct FELIX format: {"felix_type": "crypto", "class": "...", "method": "...", "details": {...}}
	// 2. Standard Frida send: {"type": "send", "payload": {"felix_type": "...", ...}}
	// 3. Standard Frida error: {"type": "error", "description": "...", "stack": "..."}

	var evt RuntimeEvent
	evt.Timestamp = time.Now().UTC()
	evt.PackageName = s.Config.TargetPackage
	evt.RawMessage = raw

	msgType, _ := genericMsg["type"].(string)
	felixType, _ := genericMsg["felix_type"].(string)

	if msgType == "error" {
		evt.Type = EventTypeError
		evt.Details = genericMsg
		desc, _ := genericMsg["description"].(string)
		s.mu.Lock()
		s.Errors = append(s.Errors, fmt.Sprintf("Frida script error: %s", desc))
		s.mu.Unlock()
	} else if msgType == "send" {
		payload, ok := genericMsg["payload"].(map[string]any)
		if !ok {
			return errors.New("missing or non-object payload in send message")
		}
		pType, _ := payload["felix_type"].(string)
		evt.Type = RuntimeEventType(pType)
		evt.Class, _ = payload["class"].(string)
		evt.Method, _ = payload["method"].(string)
		if det, ok := payload["details"].(map[string]any); ok {
			evt.Details = det
		}
	} else if felixType != "" {
		evt.Type = RuntimeEventType(felixType)
		evt.Class, _ = genericMsg["class"].(string)
		evt.Method, _ = genericMsg["method"].(string)
		if det, ok := genericMsg["details"].(map[string]any); ok {
			evt.Details = det
		}
	} else {
		// Unrecognized format
		evt.Type = EventTypeAPI
		evt.Details = genericMsg
	}

	if evt.Type == "" {
		evt.Type = EventTypeAPI
	}
	evt.ID = fmt.Sprintf("evt_%d_%d", time.Now().UnixNano(), len(s.Collected)+1)

	// Bounded dispatch
	s.mu.Lock()
	if len(s.Collected) < s.Config.MaxEvents {
		s.Collected = append(s.Collected, evt)
		select {
		case s.EventsChan <- evt:
		default:
			atomic.AddUint64(&s.droppedEvts, 1)
		}
	} else {
		atomic.AddUint64(&s.droppedEvts, 1)
	}
	s.mu.Unlock()

	return nil
}

// ConsumeReader reads lines from an io.Reader (e.g. stdout of Frida CLI process) until EOF.
func (s *FridaSession) ConsumeReader(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
			_ = s.ProcessJSONMessage(line)
		}
	}
}

// Result compiles all collected events, metadata, and evaluated findings.
func (s *FridaSession) Result() *DynamicExecutionResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	duration := int64(0)
	if !s.StartedAt.IsZero() {
		end := s.CompletedAt
		if end.IsZero() {
			end = time.Now().UTC()
		}
		duration = end.Sub(s.StartedAt).Milliseconds()
	}

	byType := make(map[string]int)
	for _, e := range s.Collected {
		byType[string(e.Type)]++
	}

	evCopy := make([]RuntimeEvent, len(s.Collected))
	copy(evCopy, s.Collected)

	errCopy := make([]string, len(s.Errors))
	copy(errCopy, s.Errors)

	evaluator := NewRuntimeFindingsEvaluator()
	findings := evaluator.EvaluateEvents(s.Config.TargetPackage, evCopy)

	status := "COMPLETED"
	if s.StateVal == SessionStateFailed {
		status = "FAILED"
	}

	return &DynamicExecutionResult{
		TargetPackage: s.Config.TargetPackage,
		Device:        s.Device,
		FridaVersion:  ScriptVersion,
		StartedAt:     s.StartedAt,
		CompletedAt:   s.CompletedAt,
		DurationMs:    duration,
		TotalEvents:   len(evCopy),
		EventsByType:  byType,
		Events:        evCopy,
		Findings:      findings,
		Errors:        errCopy,
		Status:        status,
	}
}
