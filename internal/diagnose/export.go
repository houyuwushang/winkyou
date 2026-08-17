package diagnose

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"winkyou/internal/governor"
)

const ExportRedaction = "strict"

// RedactForExport removes local paths, interface names, owner identity, trip
// attribution, and collector details while retaining the useful safety and
// capability state. It never mutates the source report.
func RedactForExport(source Report) Report {
	report := source
	report.Redaction = ExportRedaction
	report.Namespace.Path = ""
	report.Namespace.Detail = redactNamespaceDetail(report.Namespace)
	if source.MachineNamespace != nil {
		machine := *source.MachineNamespace
		machine.Path = ""
		machine.Detail = redactNamespaceDetail(machine)
		report.MachineNamespace = &machine
	}
	report.Owner = redactOwner(source.Owner)
	report.SafetyTrip = redactSafetyTrip(source.SafetyTrip)
	report.Configuration = redactConfiguration(source.Configuration)
	report.Interfaces = redactInterfaces(source.Interfaces)
	report.DefaultRoute = redactDefaultRoute(source.DefaultRoute)
	if report.UserAcknowledged != nil {
		boundary := *report.UserAcknowledged
		boundary.AllowedOperations = append([]governor.Operation(nil), source.UserAcknowledged.AllowedOperations...)
		boundary.DeniedCapabilities = append([]string(nil), source.UserAcknowledged.DeniedCapabilities...)
		boundary.Detail = ""
		report.UserAcknowledged = &boundary
	}
	if report.ActiveProbe.Detail != "" {
		if source.ActiveSTUN != nil && source.ActiveSTUN.State != ActiveSTUNStateBlocked {
			report.ActiveProbe.Detail = "explicit bounded STUN observations ran; inspect the local report for full endpoint details"
		} else {
			report.ActiveProbe.Detail = "active probing remains blocked; inspect the local report for details"
		}
	}
	if source.ActiveSTUN != nil {
		active := *source.ActiveSTUN
		active.Results = append([]ActiveSTUNTargetReport(nil), source.ActiveSTUN.Results...)
		for index := range active.Results {
			active.Results[index].TargetPrefix = redactedEndpointPrefix(active.Results[index].Target)
			active.Results[index].Target = ""
			active.Results[index].MappedPrefix = redactedEndpointPrefix(active.Results[index].MappedAddress)
			active.Results[index].MappedAddress = ""
		}
		report.ActiveSTUN = &active
	}
	return report
}

// WriteRedactedReport creates one new private JSON file. It refuses relative
// paths and existing targets, including symlinks, and removes only the file it
// created if writing fails.
func WriteRedactedReport(path string, source Report) (written int64, err error) {
	clean, err := validateExportPath(path)
	if err != nil {
		return 0, err
	}
	payload, err := json.MarshalIndent(RedactForExport(source), "", "  ")
	if err != nil {
		return 0, fmt.Errorf("encode redacted report: %w", err)
	}
	payload = append(payload, '\n')
	file, err := os.OpenFile(clean, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, fmt.Errorf("create redacted report: %w", err)
	}
	created := true
	defer func() {
		if created {
			_ = file.Close()
			_ = os.Remove(clean)
		}
	}()
	if err = writeExportPayload(file, payload); err != nil {
		return 0, err
	}
	if err = file.Sync(); err != nil {
		return 0, fmt.Errorf("sync redacted report: %w", err)
	}
	if err = file.Close(); err != nil {
		return 0, fmt.Errorf("close redacted report: %w", err)
	}
	written = int64(len(payload))
	created = false
	return written, nil
}

func validateExportPath(path string) (string, error) {
	if !utf8.ValidString(path) || strings.TrimSpace(path) == "" || strings.TrimSpace(path) != path {
		return "", errors.New("export path is invalid")
	}
	if len(path) > 4096 || strings.IndexFunc(path, unicode.IsControl) >= 0 {
		return "", errors.New("export path is invalid")
	}
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "", errors.New("export path must be absolute")
	}
	parent := filepath.Dir(clean)
	parentInfo, err := os.Stat(parent)
	if err != nil || !parentInfo.IsDir() {
		return "", errors.New("export parent directory is unavailable")
	}
	if _, err := os.Lstat(clean); err == nil {
		return "", errors.New("export target already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("export target cannot be inspected")
	}
	return clean, nil
}

func writeExportPayload(file *os.File, payload []byte) error {
	for len(payload) > 0 {
		count, err := file.Write(payload)
		if err != nil {
			return fmt.Errorf("write redacted report: %w", err)
		}
		if count <= 0 || count > len(payload) {
			return errors.New("write redacted report: short write")
		}
		payload = payload[count:]
	}
	return nil
}

func redactNamespaceDetail(status governor.NamespaceStatus) string {
	if status.Detail == "" {
		return ""
	}
	return fmt.Sprintf("%s namespace is %s; local path and validation details are redacted", status.Scope, status.State)
}

func redactOwner(status governor.OwnerStatus) governor.OwnerStatus {
	status.Owner = nil
	status.MetadataAvailable = false
	switch status.State {
	case governor.OwnerHeld:
		status.Detail = "OS lock is held; owner identity is redacted"
	case governor.OwnerIdle:
		status.Detail = "OS lock is available"
	default:
		status.Detail = "owner state is unavailable; inspect the local report for details"
	}
	return status
}

func redactSafetyTrip(status governor.SafetyTripStatus) governor.SafetyTripStatus {
	status.Detail = ""
	if status.Record.SchemaVersion == 0 {
		return status
	}
	status.Record.Detail = ""
	status.Record.PeerID = ""
	status.Record.AttemptID = ""
	status.Record.BuildVersion = ""
	status.Record.ResetNote = ""
	return status
}

func redactConfiguration(status ConfigStatus) ConfigStatus {
	if status.ExplicitPath {
		status.Source = "explicit_path_redacted"
	} else {
		status.Source = "default_path_redacted"
	}
	if status.Detail != "" {
		status.Detail = fmt.Sprintf("configuration state is %s; local source and validation details are redacted", status.State)
	}
	return status
}

func redactInterfaces(status InterfaceStatus) InterfaceStatus {
	status.Interfaces = append([]InterfaceSummary(nil), status.Interfaces...)
	for index := range status.Interfaces {
		status.Interfaces[index].Name = fmt.Sprintf("interface-%d", index+1)
		status.Interfaces[index].Index = 0
		status.Interfaces[index].AddressClasses = append([]string(nil), status.Interfaces[index].AddressClasses...)
	}
	if status.Detail != "" {
		status.Detail = "interface collection details are redacted"
	}
	return status
}

func redactDefaultRoute(status DefaultRouteStatus) DefaultRouteStatus {
	if status.Interface != "" {
		status.Interface = "interface-redacted"
	}
	if status.Source != "" {
		status.Source = "platform_route_table"
	}
	if status.Detail != "" {
		status.Detail = fmt.Sprintf("default-route state is %s; local details are redacted", status.State)
	}
	return status
}

func redactedEndpointPrefix(value string) string {
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil {
		return ""
	}
	address := endpoint.Addr().Unmap()
	bits := 48
	if address.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(address, bits).Masked().String()
}
