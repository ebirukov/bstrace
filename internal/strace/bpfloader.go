package strace

import (
	"bytes"
	"embed"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/ebirukov/bstrace"
	"io/fs"
	"log"
	"path/filepath"
)

func (l *BPFLoader) LoadBpfObjects(bpfObjs *BpfObjs) error {
	sharedSpec, err := l.LoadObjSpec("kprog/obj/common/shared.bpf.o")
	if err != nil {
		return fmt.Errorf("error reading ebpf obj file: %w", err)
	}

	if err := sharedSpec.LoadAndAssign(bpfObjs.SharedObjs, nil); err != nil {
		return fmt.Errorf("error loading shared objects: %w", err)
	}

	// load tracepoint programs
	tpProgSpec, err := l.LoadObjSpec("kprog/obj/tp/strace.bpf.o")
	if err != nil {
		return fmt.Errorf("error reading ebpf program file: %w", err)
	}

	if err = tpProgSpec.LoadAndAssign(bpfObjs.TracepointsObjs, &ebpf.CollectionOptions{
		MapReplacements: bpfObjs.SharedObjs.Maps(),
	}); err != nil {
		return fmt.Errorf("error loading ebpf tracepoint programs: %w", err)
	}

	parserCollections, err := l.LoadParsers("kprog/obj/parser", bpfObjs.SharedObjs)
	if err != nil {
		return fmt.Errorf("error loading parser programs: %w", err)
	}

	defer func() {
		for _, obj := range parserCollections {
			obj.Close()
		}
	}()

	if err := fillProgArray(parserCollections, bpfObjs.TracepointsObjs.ProgMap); err != nil {
		return fmt.Errorf("error filling parser program array: %w", err)
	}

	return nil
}

func fillProgArray(pc []*ebpf.Collection, progArray *ebpf.Map) error {
	for _, parserCollection := range pc {
		for name, program := range parserCollection.Programs {
			var syscallNR uint32

			if err := Variables(parserCollection.Variables).Get("SC_NR", &syscallNR); err != nil {
				return fmt.Errorf("can't get prog syscall number; err: %w", err)
			}

			if err := progArray.Put(syscallNR, program); err != nil {
				return fmt.Errorf("error putting program %s to map: %w", name, err)
			}

			log.Printf("Store program for syscall %d from %s to prog array", syscallNR, name)
		}
	}

	return nil
}

// LoadParsers load syscall parser programs
func (l *BPFLoader) LoadParsers(path string, sharedObjs *SharedObjs) ([]*ebpf.Collection, error) {
	dir, err := fs.ReadDir(bstrace.BpfObjFS, path)
	if err != nil {
		return nil, fmt.Errorf("error reading ebpf program directory: %w", err)
	}

	var parserCollections []*ebpf.Collection

	for _, d := range dir {
		if d.IsDir() {
			log.Printf("Skipping directory: %s", d.Name())

			continue
		}

		spec, err := l.LoadObjSpec(filepath.Join(path, d.Name()))
		if err != nil {
			return nil, fmt.Errorf("error reading ebpf program file: %w", err)
		}

		parserCollection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
			MapReplacements: sharedObjs.Maps(),
		})
		if err != nil {
			return nil, fmt.Errorf("error loading parser collection %s: %w", parserCollection, err)
		}

		parserCollections = append(parserCollections, parserCollection)
	}

	return parserCollections, nil
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
