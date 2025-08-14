package strace

import (
	"fmt"
	"github.com/cilium/ebpf"
)

type Variables map[string]*ebpf.Variable

func (vars Variables) Get(name string, value any) error {
	for scName, v := range vars {
		if scName != name {
			continue
		}

		if err := v.Get(value); err != nil {
			return fmt.Errorf("error read %s variable: %w", name, err)
		}

		return nil
	}

	return fmt.Errorf("not found variable '%s'; available vars: %v", name, vars)
}
