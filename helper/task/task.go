// task/task.go
package task

import (
	"log"
	"sync"
	"time"

	"github.com/xmplusdev/xray-core/v26/common/task"
)

// PeriodicTask wraps the xray task.Periodic with a tag identifier
type PeriodicTask struct {
	Tag      string
	*task.Periodic
	mu       sync.Mutex
	running  bool
}

// New creates a new PeriodicTask with the given tag and periodic task
func New(tag string, periodic *task.Periodic) *PeriodicTask {
	return &PeriodicTask{
		Tag:      tag,
		Periodic: periodic,
		running:  false,
	}
}

// NewWithInterval creates a new PeriodicTask with tag, interval, and execute function
func NewWithInterval(tag string, interval time.Duration, execute func() error) *PeriodicTask {
	return &PeriodicTask{
		Tag: tag,
		Periodic: &task.Periodic{
			Interval: interval,
			Execute:  execute,
		},
		running: false,
	}
}

// Start begins the periodic task execution
func (pt *PeriodicTask) Start() error {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	if pt.running {
		return nil
	}

	if pt.Periodic != nil {
		err := pt.Periodic.Start()
		if err == nil {
			pt.running = true
		}
		return err
	}
	return nil
}

// Close stops the periodic task execution
func (pt *PeriodicTask) Close() error {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	if !pt.running {
		return nil
	}

	if pt.Periodic != nil {
		err := pt.Periodic.Close()
		if err == nil {
			pt.running = false
		}
		return err
	}
	return nil
}

// IsRunning returns whether the task is currently running
func (pt *PeriodicTask) IsRunning() bool {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	return pt.running
}

// Restart stops and starts the task
func (pt *PeriodicTask) Restart() error {
	if err := pt.Close(); err != nil {
		return err
	}
	return pt.Start()
}

// Manager manages multiple periodic tasks
type Manager struct {
	tasks []*PeriodicTask
	mu    sync.RWMutex
}

// NewManager creates a new task manager
func NewManager() *Manager {
	return &Manager{
		tasks: make([]*PeriodicTask, 0),
	}
}

// Add adds a new task to the manager
func (m *Manager) Add(task *PeriodicTask) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tasks = append(m.tasks, task)
}

// StartAll starts all tasks in the manager
func (m *Manager) StartAll() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, t := range m.tasks {
		if err := t.Start(); err != nil {
			log.Printf("Failed to start task %s: %v", t.Tag, err)
			return err
		}
		log.Printf("Task %s started", t.Tag)
	}
	return nil
}

// CloseAll stops all tasks in the manager
func (m *Manager) CloseAll() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var lastErr error
	for _, t := range m.tasks {
		if err := t.Close(); err != nil {
			log.Printf("Failed to close task %s: %v", t.Tag, err)
			lastErr = err
		}
	}
	return lastErr
}

// GetTask returns a task by tag
func (m *Manager) GetTask(tag string) *PeriodicTask {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, t := range m.tasks {
		if t.Tag == tag {
			return t
		}
	}
	return nil
}

// RemoveTask removes a task by tag
func (m *Manager) RemoveTask(tag string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, t := range m.tasks {
		if t.Tag == tag {
			if err := t.Close(); err != nil {
				return err
			}
			m.tasks = append(m.tasks[:i], m.tasks[i+1:]...)
			return nil
		}
	}
	return nil
}

// Count returns the number of tasks
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tasks)
}