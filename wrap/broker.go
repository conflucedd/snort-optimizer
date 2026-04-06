package main

import "sync"

type AlertBroker struct {
	mu          sync.RWMutex
	subscribers map[chan AlertEvent]struct{}
}

func NewAlertBroker() *AlertBroker {
	return &AlertBroker{
		subscribers: make(map[chan AlertEvent]struct{}),
	}
}

func (b *AlertBroker) Subscribe() chan AlertEvent {
	ch := make(chan AlertEvent, 128)
	b.mu.Lock()
	b.subscribers[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *AlertBroker) Unsubscribe(ch chan AlertEvent) {
	b.mu.Lock()
	if _, ok := b.subscribers[ch]; ok {
		delete(b.subscribers, ch)
		close(ch)
	}
	b.mu.Unlock()
}

func (b *AlertBroker) Publish(alert AlertEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.subscribers {
		select {
		case ch <- alert:
		default:
		}
	}
}
