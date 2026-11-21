package main

import (
	"sync"
	"testing"
	"time"
)

func TestConcurrentEventSubscription(t *testing.T) {
	subsMu.Lock()
	original := subs
	subs = nil
	subsMu.Unlock()
	t.Cleanup(func() {
		subsMu.Lock()
		subs = original
		subsMu.Unlock()
	})

	const count = 16
	start := make(chan struct{})
	received := make(chan int, count)
	var workers sync.WaitGroup
	for id := 0; id < count; id++ {
		workers.Add(1)
		go func(id int) {
			defer workers.Done()
			<-start
			Subscribe(func(ev, data string) {
				if ev == "test.complete" && data == "ready" {
					received <- id
				}
			})
			Emit("test.progress", "")
		}(id)
	}
	close(start)
	workers.Wait()
	Emit("test.complete", "ready")
	deadline := time.After(2 * time.Second)
	seen := make(map[int]bool)
	for len(seen) < count {
		select {
		case id := <-received:
			if seen[id] {
				t.Fatalf("subscriber %d received the event twice", id)
			}
			seen[id] = true
		case <-deadline:
			t.Fatalf("only %d of %d subscribers received the event", len(seen), count)
		}
	}
}
