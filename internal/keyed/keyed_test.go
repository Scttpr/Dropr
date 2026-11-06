package keyed

import (
	"sync"
	"testing"
)

func TestMutex(t *testing.T) {
	t.Parallel()
	var km Mutex
	var wg sync.WaitGroup
	counter := 0
	for range 50 {
		wg.Go(func() {
			unlock := km.Lock("k")
			counter++
			unlock()
		})
	}
	wg.Wait()
	if counter != 50 || km.Len() != 0 {
		t.Fatalf("counter %d, entries %d", counter, km.Len())
	}
}
