package protocol

import (
	"testing"
	"time"
)

func TestProtocolIDRequiresNamespaceAndVersion(t *testing.T) {
	if _, err := ParseID("community.chat/1"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseID("chat"); err == nil {
		t.Fatal("accepted unnamespaced protocol id")
	}
}

func TestEnvelopeExpiry(t *testing.T) {
	now := time.Now()
	if !(Envelope{ExpiresAt: now}).Expired(now) {
		t.Fatal("packet should be expired")
	}
}
