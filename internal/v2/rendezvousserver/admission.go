package rendezvousserver

import (
	"time"

	"winkyou/internal/v2/rendezvousadmission"
)

var ErrInvalidAdmission = rendezvousadmission.ErrInvalid

type Admission = rendezvousadmission.Admission

type validatedAdmission struct {
	associationID string
	issuedAt      time.Time
	expiresAt     time.Time
}

func loadAdmission(path string, now time.Time) (validatedAdmission, error) {
	admission, err := rendezvousadmission.Load(path, now)
	if err != nil {
		return validatedAdmission{}, err
	}
	return validatedAdmission{
		associationID: admission.AssociationID,
		issuedAt:      admission.IssuedAt,
		expiresAt:     admission.ExpiresAt,
	}, nil
}

func parseAdmission(payload []byte, now time.Time) (validatedAdmission, error) {
	admission, err := rendezvousadmission.Parse(payload, now)
	if err != nil {
		return validatedAdmission{}, err
	}
	return validatedAdmission{
		associationID: admission.AssociationID,
		issuedAt:      admission.IssuedAt,
		expiresAt:     admission.ExpiresAt,
	}, nil
}
