package sdk

import (
	"context"
	"sync"
)

// A cachedValue loads a value and caches it until isValid returns false
type cachedValue[T any] struct {
	load    func(ctx context.Context) (T, error)
	isValid func(T) bool

	mu    sync.RWMutex
	ready bool
	value T
}

func newCachedValue[T any](
	load func(ctx context.Context) (T, error),
	isValid func(T) bool,
) *cachedValue[T] {
	return &cachedValue[T]{load: load, isValid: isValid}
}

func (c *cachedValue[T]) Get(ctx context.Context) (T, error) {
	// first check if the cached value is available
	c.mu.RLock()
	ready := c.ready
	value := c.value
	c.mu.RUnlock()
	if ready && c.isValid(value) {
		return value, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// check for the cached value again (double-checked locking)
	if c.ready && c.isValid(c.value) {
		return c.value, nil
	}

	// load the value
	var err error
	c.value, err = c.load(ctx)
	if err != nil {
		return c.value, err
	}
	c.ready = true

	return c.value, nil
}
