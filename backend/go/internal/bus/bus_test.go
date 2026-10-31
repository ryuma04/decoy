package bus

import "testing"

func TestFanOutAndUnsubscribe(t *testing.T) {
	b := NewMemory()
	a, stopA := b.Subscribe(4, TopicEvent, TopicFinding)
	c, stopC := b.Subscribe(4, TopicEvent)
	b.Publish(TopicEvent, 1)
	b.Publish(TopicFinding, 2)
	if m := <-a; m.Topic != TopicEvent || m.Value != 1 {
		t.Fatalf("a got %+v", m)
	}
	if m := <-a; m.Topic != TopicFinding {
		t.Fatalf("a got %+v", m)
	}
	if m := <-c; m.Value != 1 {
		t.Fatalf("c got %+v", m)
	}
	select {
	case m := <-c:
		t.Fatalf("c must not receive findings, got %+v", m)
	default:
	}
	stopC()
	stopC() // idempotent
	b.Publish(TopicEvent, 3)
	if _, ok := <-c; ok {
		t.Fatal("closed subscriber received a message")
	}
	stopA()
}

func TestPublishNeverBlocks(t *testing.T) {
	b := NewMemory()
	_, stop := b.Subscribe(1, TopicEvent)
	defer stop()
	for i := 0; i < 10; i++ {
		b.Publish(TopicEvent, i)
	}
	if b.Dropped.Load() != 9 {
		t.Fatalf("dropped = %d, want 9", b.Dropped.Load())
	}
}
