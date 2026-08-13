package architecture

import (
	"reflect"
	"testing"

	pmodel "winkyou/pkg/probe/model"
	"winkyou/pkg/solver"
)

// Compile-time assignments make a reintroduced probe/model struct definition
// fail this architecture package: these compatibility names must stay aliases
// of the canonical solver domain.
var (
	_ solver.ProbeScript = pmodel.Script{}
	_ pmodel.Script      = solver.ProbeScript{}
	_ solver.ProbeStep   = pmodel.Step{}
	_ pmodel.Step        = solver.ProbeStep{}
	_ solver.ProbeResult = pmodel.Result{}
	_ pmodel.Result      = solver.ProbeResult{}
)

func TestProbeModelNamesAliasSolverDomain(t *testing.T) {
	for name, types := range map[string][2]reflect.Type{
		"script": {reflect.TypeOf(pmodel.Script{}), reflect.TypeOf(solver.ProbeScript{})},
		"step":   {reflect.TypeOf(pmodel.Step{}), reflect.TypeOf(solver.ProbeStep{})},
		"result": {reflect.TypeOf(pmodel.Result{}), reflect.TypeOf(solver.ProbeResult{})},
	} {
		if types[0] != types[1] {
			t.Fatalf("probe model %s type = %v, want solver type %v", name, types[0], types[1])
		}
	}
}
