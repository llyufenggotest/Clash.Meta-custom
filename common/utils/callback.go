package utils

import (
	"io"
	"sync"

	list "github.com/bahlo/generic-list-go"
)

type Callback[T any] struct {
	list  list.List[*callbackRegistration[T]]
	mutex sync.RWMutex
}

func NewCallback[T any]() *Callback[T] {
	return &Callback[T]{}
}

func (c *Callback[T]) Register(item func(T)) io.Closer {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	element := c.list.PushBack(&callbackRegistration[T]{listener: item, active: true})
	return &callbackCloser[T]{
		element:  element,
		callback: c,
	}
}

// PrepareEmit snapshots listeners before entering a caller's short publication
// section. At actual launch it rechecks active registrations under the same
// RLock used by Emit. No user code runs synchronously; Close before launch
// retracts the registration, but already launched callbacks are not joined.
func (c *Callback[T]) PrepareEmit(item T) func() {
	return c.PrepareEmitGuarded(item, nil)
}

// PrepareEmitGuarded orders registration admission before the publication guard.
// The guard must synchronously execute only the launch closure, not user code.
func (c *Callback[T]) PrepareEmitGuarded(item T, guard func(func()) error) func() {
	c.mutex.RLock()
	var listeners []*callbackRegistration[T]
	for element := c.list.Front(); element != nil; element = element.Next() {
		listeners = append(listeners, element.Value)
	}
	c.mutex.RUnlock()
	return func() {
		c.mutex.RLock()
		defer c.mutex.RUnlock()
		launch := func() {
			for _, registration := range listeners {
				if registration.active {
					go registration.listener(item)
				}
			}
		}
		// Caller publication locks are acquired after the registration lock.
		// The guard only launches goroutines, never executes listener code.
		if guard != nil {
			_ = guard(launch)
		} else {
			launch()
		}
	}
}

func (c *Callback[T]) Emit(item T) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	for element := c.list.Front(); element != nil; element = element.Next() {
		go element.Value.listener(item)
	}
}

type callbackRegistration[T any] struct {
	listener func(T)
	active   bool // protected by Callback.mutex
}

type callbackCloser[T any] struct {
	element  *list.Element[*callbackRegistration[T]]
	callback *Callback[T]
	once     sync.Once
}

func (c *callbackCloser[T]) Close() error {
	c.once.Do(func() {
		c.callback.mutex.Lock()
		defer c.callback.mutex.Unlock()
		c.element.Value.active = false
		c.callback.list.Remove(c.element)
	})
	return nil
}
