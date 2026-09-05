package gatecorchestrator

import (
	"net/netip"
	"testing"

	"winkyou/internal/v2/directattempt"
)

func TestPostOOBEchoPacketBindsRoleIdentityAndAttempt(t *testing.T) {
	initiator := echoBinding{
		Role: directattempt.RoleInitiator, Local: netip.MustParseAddr("10.90.0.1"), Remote: netip.MustParseAddr("10.90.0.2"),
		AttemptID: "attempt-one", ContextDigest: [32]byte{1, 2, 3, 4},
	}
	responder := initiator
	responder.Role = directattempt.RoleResponder
	responder.Local, responder.Remote = initiator.Remote, initiator.Local
	nonce := [8]byte{3, 1, 4, 1, 5, 9, 2, 6}
	request, err := buildEchoPacket(initiator, echoRequest, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(request) != echoPacketSize || len(request)-28 != echoPayloadSize {
		t.Fatalf("echo packet/payload = %d/%d", len(request), len(request)-28)
	}
	message, err := parseEchoPacket(request, responder, echoRequest, nil)
	if err != nil || message.Nonce != nonce || message.Role != directattempt.RoleInitiator {
		t.Fatalf("request message=%+v err=%v", message, err)
	}
	response, err := buildEchoPacket(responder, echoResponse, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseEchoPacket(response, initiator, echoResponse, &nonce); err != nil {
		t.Fatal(err)
	}

	mutations := []struct {
		name string
		edit func([]byte, *echoBinding)
	}{
		{"replay direction", func(packet []byte, _ *echoBinding) { packet[28+5] = byte(echoClose) }},
		{"wrong role", func(packet []byte, _ *echoBinding) { packet[28+6] = encodeEchoRole(directattempt.RoleResponder) }},
		{"wrong source", func(_ []byte, binding *echoBinding) { binding.Remote = netip.MustParseAddr("10.90.0.3") }},
		{"wrong destination", func(_ []byte, binding *echoBinding) { binding.Local = netip.MustParseAddr("10.90.0.3") }},
		{"wrong context", func(_ []byte, binding *echoBinding) { binding.ContextDigest[0] ^= 0xff }},
		{"wrong attempt", func(_ []byte, binding *echoBinding) { binding.AttemptID = "attempt-two" }},
		{"truncated length", func(packet []byte, _ *echoBinding) { packet[3] = 0 }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			packet := append([]byte(nil), request...)
			binding := responder
			mutation.edit(packet, &binding)
			if _, err := parseEchoPacket(packet, binding, echoRequest, nil); err == nil {
				t.Fatal("mutated echo was accepted")
			}
		})
	}
}
