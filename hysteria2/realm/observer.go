package realm

import "net/netip"

// PunchObserver receives read-only notifications from the server-side (answering)
// punch engine. It exists so an embedding binary can measure hole punching — did
// the peer's packet reach us? did we answer? — without the engine knowing anything
// about trace assembly or reporting.
//
// Contract:
//   - Options.Observer nil (the default) disables observation entirely; every
//     hook site is nil-checked, so the production path behaves exactly as before.
//   - Callbacks run synchronously on punch hot paths. Implementations MUST be
//     fast and non-blocking (grab a timestamp, update a map, return).
//   - attemptID is the engine-local ID of one answer attempt; metadata carries
//     the nonce, the only identifier shared with the initiating peer.
type PunchObserver interface {
	// PunchRequested fires when a rendezvous punch event arrives, right before
	// the engine starts answering. localAddresses is this node's own reflexive
	// (STUN) addresses at that moment; empty when discovery failed.
	PunchRequested(attemptID string, metadata PunchMetadata, peerAddresses []netip.AddrPort, localAddresses []netip.AddrPort)

	// PunchPacketReceived fires for every valid punch packet decoded on the
	// shared conn (packetType is PunchHello or PunchAck). The first call per
	// attempt proves the peer's traffic reached us; from is the peer's NAT
	// mapping as we observe it.
	PunchPacketReceived(attemptID string, from netip.AddrPort, packetType byte)

	// PunchAckSent fires right after the engine answers a Hello with an Ack.
	PunchAckSent(attemptID string, to netip.AddrPort)

	// PunchFinished fires when the answer attempt ends. err == nil means the
	// engine considered the punch successful (result holds the winning peer
	// address); err != nil is usually the answer timeout.
	PunchFinished(attemptID string, result PunchResult, err error)
}
