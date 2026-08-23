package initserver

import (
	"fmt"
	"strconv"
	"sync"
)

// StepState is the outcome of one provisioning/hardening step.
type StepState string

const (
	StepRunning StepState = "running"
	StepOK      StepState = "ok"
	StepError   StepState = "error"
	StepSkipped StepState = "skipped"
)

// Step is one line in the smart console: a named action with its state and, on
// failure, a plain-language hint explaining what went wrong and how to fix it.
type Step struct {
	Name   string    `json:"name"`
	State  StepState `json:"state"`
	Detail string    `json:"detail,omitempty"`
	Hint   string    `json:"hint,omitempty"`
}

// JobView is a serializable snapshot of a Job for the API/UI.
type JobView struct {
	ID       string         `json:"id"`
	Kind     string         `json:"kind"`
	ServerID string         `json:"server_id,omitempty"`
	Steps    []Step         `json:"steps"`
	Console  []string       `json:"console"`
	Done     bool           `json:"done"`
	OK       bool           `json:"ok"`
	Result   map[string]any `json:"result,omitempty"`
}

// Job tracks a running provision/harden operation: an ordered list of steps plus
// a verbose console log. Safe for the worker goroutine to mutate while the API
// reads snapshots.
type Job struct {
	id       string
	kind     string
	serverID string

	mu      sync.Mutex
	steps   []Step
	console []string
	done    bool
	ok      bool
	result  map[string]any
}

// ID returns the job id.
func (j *Job) ID() string { return j.id }

// Logf appends a verbose console line (shown in the smart console).
func (j *Job) Logf(format string, a ...any) {
	line := fmt.Sprintf(format, a...)
	j.mu.Lock()
	j.console = append(j.console, line)
	j.mu.Unlock()
}

// Start opens a new step in the "running" state and logs it.
func (j *Job) Start(name string) {
	j.mu.Lock()
	j.steps = append(j.steps, Step{Name: name, State: StepRunning})
	j.console = append(j.console, "▶ "+name)
	j.mu.Unlock()
}

// OK marks the current step done.
func (j *Job) OK(detail string) {
	j.mu.Lock()
	if n := len(j.steps); n > 0 {
		j.steps[n-1].State = StepOK
		j.steps[n-1].Detail = detail
	}
	if detail != "" {
		j.console = append(j.console, "  ✓ "+detail)
	} else {
		j.console = append(j.console, "  ✓ ok")
	}
	j.mu.Unlock()
}

// Fail marks the current step errored with a plain-language hint.
func (j *Job) Fail(detail, hint string) {
	j.mu.Lock()
	if n := len(j.steps); n > 0 {
		j.steps[n-1].State = StepError
		j.steps[n-1].Detail = detail
		j.steps[n-1].Hint = hint
	}
	j.console = append(j.console, "  ✗ "+detail)
	if hint != "" {
		j.console = append(j.console, "    → "+hint)
	}
	j.mu.Unlock()
}

// Skip records a step that was not run.
func (j *Job) Skip(name, detail string) {
	j.mu.Lock()
	j.steps = append(j.steps, Step{Name: name, State: StepSkipped, Detail: detail})
	j.console = append(j.console, "∅ "+name+" — "+detail)
	j.mu.Unlock()
}

// Output appends raw command output to the console, indented.
func (j *Job) Output(s string) {
	if s == "" {
		return
	}
	j.mu.Lock()
	j.console = append(j.console, "  | "+s)
	j.mu.Unlock()
}

// Finish closes the job with an overall result.
func (j *Job) Finish(ok bool, result map[string]any) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.done {
		return // idempotent: a finished job is never overwritten (e.g. by panic recovery)
	}
	j.done = true
	j.ok = ok
	j.result = result
	if ok {
		j.console = append(j.console, "● done")
	} else {
		j.console = append(j.console, "● finished with errors")
	}
}

// Snapshot returns a copy safe to serialize.
func (j *Job) Snapshot() JobView {
	j.mu.Lock()
	defer j.mu.Unlock()
	steps := make([]Step, len(j.steps))
	copy(steps, j.steps)
	console := make([]string, len(j.console))
	copy(console, j.console)
	result := make(map[string]any, len(j.result))
	for k, v := range j.result {
		result[k] = v
	}
	return JobView{
		ID: j.id, Kind: j.kind, ServerID: j.serverID,
		Steps: steps, Console: console, Done: j.done, OK: j.ok, Result: result,
	}
}

// maxJobHistory is the rolling cap on jobs the manager keeps in memory.
// Once full, the oldest job is evicted on every New() call (FIFO).
const maxJobHistory = 32

// JobManager keeps recent jobs addressable by id for the UI to poll.
type JobManager struct {
	mu    sync.Mutex
	jobs  map[string]*Job
	order []string // creation order, for bounded-cap eviction
	seq   int
}

// NewJobManager builds an empty manager.
func NewJobManager() *JobManager { return &JobManager{jobs: map[string]*Job{}} }

// New creates and registers a job, returning it for the worker to drive.
func (m *JobManager) New(kind, serverID string) *Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	j := &Job{id: "job-" + strconv.Itoa(m.seq), kind: kind, serverID: serverID}
	m.jobs[j.id] = j
	m.order = append(m.order, j.id)
	// Keep memory bounded: evict the genuinely oldest job (by creation order, not
	// by string-compared id — "job-10" sorts before "job-9" lexically).
	if len(m.order) > maxJobHistory {
		old := m.order[0]
		m.order = m.order[1:]
		delete(m.jobs, old)
	}
	return j
}

// Get returns a job by id.
func (m *JobManager) Get(id string) (*Job, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	return j, ok
}
