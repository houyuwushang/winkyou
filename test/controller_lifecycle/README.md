This branch is an independent controller review, separate from the field image repair.

`accepted-r4.py` preserves the reviewed controller bytes. `stage3-outer.py` is a proposed lifecycle revision, not an installed or approved field tool. It removes the unnecessary unshare fork, explicitly handles stop requests, reaps exited children while retaining a failure, and requires an identity-bound release receipt plus empty owned resources. It never retries an operation, signals a child, upgrades a signal, or performs failure cleanup.

The Ubuntu 22.04 disposable proof uses the real FIFO/holder/setsid/Python/unshare startup chain. Before invoking either source, it replaces only `Controller.run` with a synthetic lifecycle fixture. No field run, pairing, router, launcher, or SSH service is reachable. The baseline exits through a cooperative pipe after demonstrating inherited ignored signals; it uses no HUP or KILL. The candidate must retain the first failure, reject a signal without a receipt, reap its synthetic guardian and worker, preserve the guardian's output, accept a separate verified release, and leave no namespace or descriptor holder. All fixture processes are tracked by exact identity and reaped.

The release receipt is reviewed input, not an authentication mechanism. It contains the controller identity, first-stop hash, both explicit release confirmations, and the hash of separately reviewed cleanup evidence. Cleanup itself still needs independent authorization. Sending a stop request does not authorize router teardown or anchor deletion.

Passing this proof does not authorize installation, modification of an old instance, or a new field execution.
