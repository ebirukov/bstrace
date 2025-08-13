package strace

import (
	"bytes"
	"embed"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/ebirukov/bstrace"
	"io/fs"
	"log"
)

func (l *BPFLoader) LoadBpfObjects(tpProgObjs any) error {
	sharedSpec, err := l.LoadObjSpec("kprog/obj/common/shared.bpf.o")
	if err != nil {
		return fmt.Errorf("error reading ebpf obj file: %w", err)
	}

	sharedObjs := struct {
		SysCallDataMap *ebpf.Map `ebpf:"sc_data"`
	}{}

	if err := sharedSpec.LoadAndAssign(&sharedObjs, nil); err != nil {
		return fmt.Errorf("error loading shared objects: %w", err)
	}

	var scDataMap = sharedObjs.SysCallDataMap

	defer scDataMap.Close()

	// load tracepoint programs
	tpProgSpec, err := l.LoadObjSpec("kprog/obj/tp/strace.bpf.o")
	if err != nil {
		return fmt.Errorf("error reading ebpf program file: %w", err)
	}

	err = tpProgSpec.LoadAndAssign(tpProgObjs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"sc_data": scDataMap,
		},
	})
	if err != nil {
		return fmt.Errorf("error loading ebpf tracepoint programs: %w", err)
	}

	return nil
}

// LoadParsers load syscall parser programs
func (l *BPFLoader) LoadParsers(progMap *ebpf.Map, scDataMap *ebpf.Map) error {
	dir, err := fs.ReadDir(bstrace.BpfObjFS, "kprog/obj/parser")
	if err != nil {
		return fmt.Errorf("error reading ebpf program directory: %w", err)
	}

	var parserCollections []*ebpf.Collection

	defer func() {
		for _, obj := range parserCollections {
			obj.Close()
		}
	}()

	for _, d := range dir {
		if d.IsDir() {
			log.Printf("Skipping directory: %s", d.Name())

			continue
		}

		spec, err := l.LoadObjSpec("kprog/obj/parser/" + d.Name())
		if err != nil {
			return fmt.Errorf("error reading ebpf program file: %w", err)
		}

		parserCollection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
			MapReplacements: map[string]*ebpf.Map{
				"sc_data": scDataMap,
			},
		})
		if err != nil {
			return fmt.Errorf("error loading parser collection %s: %w", parserCollection, err)
		}

		parserCollections = append(parserCollections, parserCollection)

		for name, program := range parserCollection.Programs {
			var syscallNR uint32

			for scName, v := range parserCollection.Variables {
				if scName == "SC_NR" {
					if err := v.Get(&syscallNR); err != nil {
						return fmt.Errorf("error read %s variable for func %s: %w; var spec: %v", scName, name, err, parserCollection.Variables)
					}
					break
				}

				log.Printf("Not found variable '%s' for func %s; available var: %v", scName, name, parserCollection.Variables)
			}

			err = progMap.Put(syscallNR, program)
			if err != nil {
				return fmt.Errorf("error putting program %s to map: %w", name, err)
			}

			log.Printf("Store program syscall %d from %s to prog array", syscallNR, name)
		}
	}

	return nil
}

type BPFLoader struct {
	fs embed.FS
}

func NewLoader(fs embed.FS) *BPFLoader {
	return &BPFLoader{fs: fs}
}

func (l *BPFLoader) LoadObjSpec(file string) (*ebpf.CollectionSpec, error) {
	data, err := l.fs.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("could not read embedded bpf object: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("error reading ebpf program file: %w", err)
	}

	return spec, err
}
