// Package umc provides a small, dependency-free Go client for the UMC local
// Control API. Payloads are protobuf bytes from api/umc.proto; the client owns
// framing, hello negotiation, request correlation, and status handling.
package umc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const maxEnvelope = 4 * 1024 * 1024

// Status is the status carried by a Control API response.
type Status struct {
	Code    uint64
	Message string
}

// Response is one correlated Control API response.
type Response struct {
	RequestID uint64
	Status    Status
	Payload   []byte
}

// StatusError reports a non-OK daemon response.
type StatusError struct {
	Status Status
}

func (e *StatusError) Error() string {
	if e.Status.Message == "" {
		return fmt.Sprintf("umc control status %d", e.Status.Code)
	}
	return fmt.Sprintf("umc control status %d: %s", e.Status.Code, e.Status.Message)
}

// Client is safe for concurrent callers; requests are serialized because the
// local Control API is an ordered framed stream.
type Client struct {
	conn        net.Conn
	mu          sync.Mutex
	sequence    uint64
	requestID   uint64
	envelopeMax uint32
}

// Dial connects to a Unix-domain Control API socket and negotiates API 1.0.
func Dial(ctx context.Context, endpoint, clientName string) (*Client, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", endpoint)
	if err != nil {
		return nil, err
	}
	client := newClient(conn)
	if err := client.hello(clientName); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return client, nil
}

// New wraps an already-connected stream and performs the Control API hello.
// It is useful for tests and platform-specific transports.
func New(conn net.Conn, clientName string) (*Client, error) {
	client := newClient(conn)
	if err := client.hello(clientName); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return client, nil
}

func newClient(conn net.Conn) *Client {
	return &Client{conn: conn, sequence: 1, envelopeMax: maxEnvelope}
}

// Request sends one raw Control API request. Payload encoding/decoding stays
// with the caller so generated protobuf types can be used without a runtime
// dependency in this binding.
func (c *Client) Request(ctx context.Context, service, method string, payload []byte, deadlineUnixMs int64) (Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return Response{}, errors.New("umc client is closed")
	}
	c.requestID++
	id := c.requestID
	request := encodeRequest(id, service, method, payload, deadlineUnixMs)
	if err := c.writeFrame(ctx, encodeEnvelope(12, request)); err != nil {
		return Response{}, err
	}
	for {
		frame, err := c.readFrame(ctx)
		if err != nil {
			return Response{}, err
		}
		body, ok := fieldBytes(frame, 13)
		if !ok {
			continue
		}
		response, err := decodeResponse(body)
		if err != nil {
			return Response{}, err
		}
		if response.RequestID != id {
			continue
		}
		return response, nil
	}
}

// RequestChecked is Request with non-OK statuses converted to StatusError.
func (c *Client) RequestChecked(ctx context.Context, service, method string, payload []byte, deadlineUnixMs int64) ([]byte, error) {
	response, err := c.Request(ctx, service, method, payload, deadlineUnixMs)
	if err != nil {
		return nil, err
	}
	if response.Status.Code != 0 {
		return nil, &StatusError{Status: response.Status}
	}
	return response.Payload, nil
}

// GetStatus returns the encoded NodeAdmin.GetStatusResponse payload.
func (c *Client) GetStatus(ctx context.Context) ([]byte, error) {
	return c.RequestChecked(ctx, "NodeAdmin", "GetStatus", nil, 0)
}

// RegisterApplicationRequest encodes the stable application-registration
// request shape from api/umc.proto.
func RegisterApplicationRequest(name string, protocolIDs []string, resumable bool) []byte {
	var out []byte
	out = appendString(out, 1, name)
	for _, protocolID := range protocolIDs {
		out = appendString(out, 4, protocolID)
	}
	if resumable {
		out = appendVarint(out, 6, 1)
	}
	return out
}

// Close closes the local Control API connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

func (c *Client) hello(clientName string) error {
	hello := encodeClientHello(clientName)
	if err := c.writeFrame(context.Background(), encodeEnvelope(10, hello)); err != nil {
		return err
	}
	frame, err := c.readFrame(context.Background())
	if err != nil {
		return err
	}
	serverHello, ok := fieldBytes(frame, 11)
	if !ok {
		return errors.New("umc control hello rejected")
	}
	selected, ok := fieldBytes(serverHello, 1)
	if !ok {
		return errors.New("umc control hello omitted selected version")
	}
	major, _, ok := readVarintField(selected, 1)
	if !ok || major != 1 {
		return errors.New("unsupported UMC Control API version")
	}
	if negotiated, _, ok := readVarintField(serverHello, 7); ok && negotiated >= 1024 && negotiated < maxEnvelope {
		c.envelopeMax = uint32(negotiated)
	}
	return nil
}

func (c *Client) writeFrame(ctx context.Context, payload []byte) error {
	if len(payload) == 0 || len(payload) > int(c.envelopeMax) {
		return errors.New("invalid UMC envelope size")
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetWriteDeadline(deadline)
		defer func() { _ = c.conn.SetWriteDeadline(time.Time{}) }()
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(payload)))
	if _, err := c.conn.Write(prefix[:]); err != nil {
		return err
	}
	_, err := c.conn.Write(payload)
	return err
}

func (c *Client) readFrame(ctx context.Context) ([]byte, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetReadDeadline(deadline)
		defer func() { _ = c.conn.SetReadDeadline(time.Time{}) }()
	}
	var prefix [4]byte
	if _, err := io.ReadFull(c.conn, prefix[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length == 0 || length > c.envelopeMax {
		return nil, errors.New("invalid UMC envelope length")
	}
	payload := make([]byte, length)
	_, err := io.ReadFull(c.conn, payload)
	return payload, err
}

type field struct {
	number uint64
	wire   uint64
	value  []byte
}

func fields(data []byte) ([]field, error) {
	var out []field
	for len(data) > 0 {
		key, n, ok := takeVarint(data)
		if !ok || key == 0 {
			return nil, errors.New("invalid protobuf field key")
		}
		data = data[n:]
		number, wire := key>>3, key&7
		var value []byte
		switch wire {
		case 0:
			_, n, ok = takeVarint(data)
			if !ok {
				return nil, errors.New("invalid protobuf varint")
			}
			value = append([]byte(nil), data[:n]...)
		case 2:
			length, m, ok := takeVarint(data)
			if !ok || length > uint64(len(data)-m) {
				return nil, errors.New("invalid protobuf length")
			}
			value = append([]byte(nil), data[m:m+int(length)]...)
			n = m + int(length)
		case 1:
			if len(data) < 8 {
				return nil, errors.New("invalid fixed64 field")
			}
			value, n = data[:8], 8
		case 5:
			if len(data) < 4 {
				return nil, errors.New("invalid fixed32 field")
			}
			value, n = data[:4], 4
		default:
			return nil, errors.New("unsupported protobuf wire type")
		}
		out = append(out, field{number: number, wire: wire, value: value})
		data = data[n:]
	}
	return out, nil
}

func fieldBytes(data []byte, number uint64) ([]byte, bool) {
	parsed, err := fields(data)
	if err != nil {
		return nil, false
	}
	for _, item := range parsed {
		if item.number == number && item.wire == 2 {
			return item.value, true
		}
	}
	return nil, false
}

func readVarintField(data []byte, number uint64) (uint64, int, bool) {
	parsed, err := fields(data)
	if err != nil {
		return 0, 0, false
	}
	for _, item := range parsed {
		if item.number == number && item.wire == 0 {
			value, _, ok := takeVarint(item.value)
			return value, 0, ok
		}
	}
	return 0, 0, false
}

func decodeResponse(data []byte) (Response, error) {
	requestID, _, ok := readVarintField(data, 1)
	if !ok {
		return Response{}, errors.New("response omitted request id")
	}
	status := Status{}
	if encoded, ok := fieldBytes(data, 2); ok {
		if code, _, exists := readVarintField(encoded, 1); exists {
			status.Code = code
		}
		if message, exists := fieldBytes(encoded, 2); exists {
			status.Message = string(message)
		}
	}
	payload, _ := fieldBytes(data, 3)
	return Response{RequestID: requestID, Status: status, Payload: payload}, nil
}

func encodeClientHello(clientName string) []byte {
	version := appendVarint(nil, 1, 1)
	version = appendVarint(version, 2, 0)
	out := appendMessage(nil, 1, version)
	return appendString(out, 2, clientName)
}

func encodeRequest(id uint64, service, method string, payload []byte, deadline int64) []byte {
	out := appendVarint(nil, 1, id)
	out = appendString(out, 2, service)
	out = appendString(out, 3, method)
	if deadline > 0 {
		out = appendVarint(out, 4, uint64(deadline))
	}
	if len(payload) > 0 {
		out = appendBytes(out, 6, payload)
	}
	return out
}

func encodeEnvelope(bodyField uint64, body []byte) []byte {
	version := appendVarint(nil, 1, 1)
	version = appendVarint(version, 2, 0)
	out := appendMessage(nil, 1, version)
	out = appendVarint(out, 2, 1)
	return appendMessage(out, bodyField, body)
}

func appendKey(out []byte, number, wire uint64) []byte {
	return appendVarintRaw(out, number<<3|wire)
}

func appendVarint(out []byte, number, value uint64) []byte {
	out = appendKey(out, number, 0)
	return appendVarintRaw(out, value)
}

func appendVarintRaw(out []byte, value uint64) []byte {
	for value >= 0x80 {
		out = append(out, byte(value)|0x80)
		value >>= 7
	}
	return append(out, byte(value))
}

func appendString(out []byte, number uint64, value string) []byte {
	return appendBytes(out, number, []byte(value))
}

func appendBytes(out []byte, number uint64, value []byte) []byte {
	out = appendKey(out, number, 2)
	out = appendVarintRaw(out, uint64(len(value)))
	return append(out, value...)
}

func appendMessage(out []byte, number uint64, value []byte) []byte {
	return appendBytes(out, number, value)
}

func takeVarint(data []byte) (uint64, int, bool) {
	var value uint64
	for i, b := range data {
		if i == 10 {
			return 0, 0, false
		}
		value |= uint64(b&0x7f) << (7 * i)
		if b < 0x80 {
			return value, i + 1, true
		}
	}
	return 0, 0, false
}
