package probeio

// RevokeForTerminal irreversibly closes every probe handle and drains local
// operations before a terminal caller performs durable I/O. It stops the probe
// duration watchdog, but deliberately retains the attempt and every drain owned
// by another component. The caller must still record its durable FINISH and
// close the attempt afterwards; this operation neither refunds nor promotes it.
//
// Only the reviewed loopback carrier terminal path may use this API. It is not
// a completion phase or a transport handoff, and returns no reusable capability.
// Repeated calls are safe, including after terminal promotion or cancellation.
func (c *Controller) RevokeForTerminal() error {
	if c == nil {
		return nil
	}
	c.stopLocal()
	// The existing handoff notification also represents revoked probe handles
	// whose caller deliberately retains the attempt until durable FINISH.
	c.handoffOnce.Do(func() { close(c.handoffDone) })
	<-c.watchDone
	// watchDone closes before the watcher's deferred Complete. Explicitly join
	// the idempotent completion so this API cannot return before our own drain.
	return c.drain.Complete()
}
