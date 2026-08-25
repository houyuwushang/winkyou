//go:build !windows

package pairgen

import "context"

func writeClipboard(context.Context, []byte) error { return ErrClipboardUnavailable }
