package version

import (
	"fmt"
	"runtime"
)

var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
)

type Info struct {
	Version   string
	Commit    string
	BuildTime string
	GoVersion string
}

func Current() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuildTime: BuildTime,
		GoVersion: runtime.Version(),
	}
}

func String() string {
	info := Current()
	return fmt.Sprintf(
		"wink version %s (commit: %s, built: %s, go: %s)",
		info.Version,
		info.Commit,
		info.BuildTime,
		info.GoVersion,
	)
}

