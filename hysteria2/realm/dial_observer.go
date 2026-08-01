package realm

import "net/netip"

// DialObserver receives read-only notifications from the client-side
// (initiating) realm punch flow — the mirror of PunchObserver, which covers the
// answering side.
//
// It exists because hysteria2 is the only protocol whose realm punching runs
// inside sing-quic's own client orchestration (Client.offerNewRealm), not in the
// embedding binary. Without these hooks a hysteria2 dial can report nothing but
// success/failure: no stage timings, and no nonce to pair with the receiver's
// trace. Every other protocol gets that from the kernel's own realm transport.
//
// Contract (identical to PunchObserver):
//   - Options.DialObserver nil (the default) disables observation entirely;
//     every hook site is nil-checked, so the production dial path is unchanged.
//   - Callbacks run synchronously on the dial path. Implementations MUST be
//     fast and non-blocking (stamp a time, store a value, return).
//   - Stage boundaries are reported as events, not durations — the observer
//     owns the clock, so it can compute whatever intervals it needs.
type DialObserver interface {
	// STUNDiscovered fires after reflexive address discovery, with this
	// client's own srflx addresses. Marks the end of the STUN stage.
	STUNDiscovered(localAddresses []netip.AddrPort)

	// RendezvousDone fires after the rendezvous returns the peer's candidate
	// addresses and the punch metadata both sides will use. metadata carries
	// the nonce — the join key against the receiver's trace.
	//
	// ★ This is the metadata that punching actually uses (the server's), not
	// the one the client generated locally; pairing depends on reporting this
	// one.
	RendezvousDone(peerAddresses []netip.AddrPort, metadata PunchMetadata)

	// PunchAttempted fires once per address family before its punch race
	// starts, with the candidates that family will try.
	PunchAttempted(family string, candidates []netip.AddrPort)

	// PunchSettled fires when the punch race ends. On success family is the
	// winning family and err is nil; on failure err explains why.
	PunchSettled(family string, result PunchResult, err error)
}
