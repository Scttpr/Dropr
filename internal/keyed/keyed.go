// Package keyed provides a mutex per key without unbounded growth: an entry
// exists only while someone holds or waits for its key.
package keyed

import "sync"

// Mutex serializes work per key. The zero value is ready to use.
type Mutex struct {
	mu sync.Mutex
	m  map[string]*entry
}

type entry struct {
	mu   sync.Mutex
	refs int
}

// Lock blocks until key is free, takes it and returns the function that
// releases it.
func (k *Mutex) Lock(key string) (unlock func()) {
	k.mu.Lock()
	if k.m == nil {
		k.m = make(map[string]*entry)
	}
	e := k.m[key]
	if e == nil {
		e = &entry{}
		k.m[key] = e
	}
	e.refs++
	k.mu.Unlock()

	e.mu.Lock()
	return func() {
		e.mu.Unlock()
		k.mu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(k.m, key)
		}
		k.mu.Unlock()
	}
}

// Len returns the number of keys currently held or waited for (tests).
func (k *Mutex) Len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.m)
}
