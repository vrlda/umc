// Package protocol defines application-independent wire concepts. It does not
// interpret application payloads.
package protocol

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/openmesh/core/identity"
)

type ID string

func ParseID(value string) (ID, error) {
	value = strings.TrimSpace(value)
	separator := strings.LastIndexByte(value, '/')
	if len(value) < 3 || len(value) > 255 || separator < 1 || separator == len(value)-1 {
		return "", errors.New("protocol: id must be a namespaced value such as community.chat/1")
	}
	version, err := strconv.ParseUint(value[separator+1:], 10, 32)
	if err != nil || version == 0 {
		return "", errors.New("protocol: id must be a namespaced value such as community.chat/1")
	}
	return ID(value), nil
}

type PacketID [16]byte

type Priority uint8

const (
	PriorityBulk Priority = iota
	PriorityNormal
	PriorityInteractive
	PriorityControl
)

// Envelope contains only metadata required to route and bound an opaque packet.
// Authentication and payload encryption are applied by the secure packet layer.
type Envelope struct {
	Version       uint8
	Destination   identity.ID
	Source        *identity.ID
	ReturnToken   []byte
	PacketID      PacketID
	ExpiresAt     time.Time
	HopLimit      uint8
	Priority      Priority
	Fragment      uint16
	FragmentCount uint16
	Protocol      ID
	Payload       []byte
	Auth          []byte
}

func (e Envelope) Expired(now time.Time) bool {
	return !e.ExpiresAt.IsZero() && !now.Before(e.ExpiresAt)
}
