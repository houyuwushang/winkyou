//go:build !linux && fieldc1c

package gatecorchestrator

import (
	"context"
	"io"
	"winkyou/internal/v2/fieldc1c"
)

func RunFieldInitiator(context.Context, string) (FieldSummary, error) {
	return invalidFieldSummary(), fieldc1c.ErrInvalid
}
func RunFieldResponder(context.Context, io.Reader, io.Writer) (FieldSummary, error) {
	return invalidFieldSummary(), fieldc1c.ErrInvalid
}
