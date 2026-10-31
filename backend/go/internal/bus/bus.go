// Package bus is the typed in-process pub/sub connecting ingest, intel, alerter and the SSE hub (05 §Bus).
package bus

import (
	"log/slog"
	"sync"
	"sync/atomic"
)

type Topic string

const (
	TopicEvent     Topic = "event"
	TopicFinding   Topic = "finding"
	TopicActor     Topic = "actor"
	TopicIncident  Topic = "incident"
	TopicMaze      Topic = "maze"
	TopicSensor    Topic = "sensor"
	TopicNarrative Topic = "narrative"
)

// AllTopics is what the SSE hub subscribes to.
var AllTopics = []Topic{TopicEvent, TopicFinding, TopicActor, TopicIncident, TopicMaze, TopicSensor, TopicNarrative}

// Message carries the topic with its payload so one subscriber can listen to many topics.
type Message struct {
	Topic Topic
	Value any
}

type Bus interface {
	Publish(t Topic, v any)
	Subscribe(buf int, topics ...Topic) (<-chan Message, func())
}

// Memory is a fan-out bus over buffered channels. Publish never blocks: a full subscriber drops the
// message (the row is already stored, so `replay` can recover).
type Memory struct {
	mu      sync.RWMutex
	subs    map[Topic]map[int]chan Message
	next    int
	Dropped atomic.Int64
}

func NewMemory() *Memory {
	return &Memory{subs: map[Topic]map[int]chan Message{}}
}

func (b *Memory) Publish(t Topic, v any) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subs[t] {
		select {
		case ch <- Message{Topic: t, Value: v}:
		default:
			if b.Dropped.Add(1)%100 == 1 {
				slog.Warn("bus subscriber full, dropping", "topic", t, "dropped_total", b.Dropped.Load())
			}
		}
	}
}

// Subscribe returns a channel for the given topics and a function that unsubscribes and closes it.
func (b *Memory) Subscribe(buf int, topics ...Topic) (<-chan Message, func()) {
	ch := make(chan Message, buf)
	b.mu.Lock()
	id := b.next
	b.next++
	for _, t := range topics {
		if b.subs[t] == nil {
			b.subs[t] = map[int]chan Message{}
		}
		b.subs[t][id] = ch
	}
	b.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			b.mu.Lock()
			for _, t := range topics {
				delete(b.subs[t], id)
			}
			b.mu.Unlock()
			close(ch)
		})
	}
}
