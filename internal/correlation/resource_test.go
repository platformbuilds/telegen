package correlation

import (
	"testing"
	"time"
)

func TestResourceCorrelatorUnregisterByContainerID(t *testing.T) {
	t.Parallel()

	rc := NewResourceCorrelator(nil)
	identity := &ResourceIdentity{
		ServiceName:      "checkout",
		ServiceNamespace: "payments",
		ServiceInstance:  "checkout-abc123",
		ContainerID:      "container-123",
		PodName:          "checkout-abc123",
		K8sNamespace:     "prod",
	}
	resource := NewResource().WithAttribute("service.name", "checkout")
	rc.Register(identity, resource)

	if _, ok := rc.GetByService("checkout", "payments"); !ok {
		t.Fatal("expected service lookup to succeed after register")
	}
	if _, ok := rc.GetByContainerID("container-123"); !ok {
		t.Fatal("expected container lookup to succeed after register")
	}
	if _, ok := rc.GetByPod("prod", "checkout-abc123"); !ok {
		t.Fatal("expected pod lookup to succeed after register")
	}

	rc.UnregisterByContainerID("container-123")

	if _, ok := rc.Get(identity.Key()); ok {
		t.Fatal("expected key lookup to fail after unregister")
	}
	if _, ok := rc.GetByService("checkout", "payments"); ok {
		t.Fatal("expected service lookup to fail after unregister")
	}
	if _, ok := rc.GetByContainerID("container-123"); ok {
		t.Fatal("expected container lookup to fail after unregister")
	}
	if _, ok := rc.GetByPod("prod", "checkout-abc123"); ok {
		t.Fatal("expected pod lookup to fail after unregister")
	}
}

func TestResourceCorrelatorSweepExpiresEntries(t *testing.T) {
	t.Parallel()

	rc := NewResourceCorrelator(nil)
	identity := &ResourceIdentity{
		ServiceName:      "search",
		ServiceNamespace: "platform",
		ServiceInstance:  "search-xyz",
		ContainerID:      "container-xyz",
		PodName:          "search-xyz",
		K8sNamespace:     "prod",
	}
	resource := NewResource().WithAttribute("service.name", "search")
	rc.Register(identity, resource)

	rc.mu.Lock()
	rc.entryTTL = time.Millisecond
	rc.sweepEvery = time.Millisecond
	rc.lastSeen[identity.Key()] = time.Now().Add(-time.Second)
	rc.lastSweep = time.Now().Add(-time.Second)
	rc.mu.Unlock()

	if _, ok := rc.Get(identity.Key()); ok {
		t.Fatal("expected entry to expire during sweep")
	}
	if _, ok := rc.GetByContainerID("container-xyz"); ok {
		t.Fatal("expected container index to be cleaned after expiry sweep")
	}
}
