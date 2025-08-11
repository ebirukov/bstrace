package strace

import (
	"github.com/cilium/ebpf"
	"github.com/ebirukov/bstrace"
	"io/fs"
	"log"
)

func LoadBpfObjects() (TracepointsObjs, error) {
	sharedSpec, err := ebpf.LoadCollectionSpec("kprog/obj/common/shared.bpf.o")
	if err != nil {
		log.Fatalf("Error reading ebpf program file: %v", err)
	}

	sharedObjs := struct {
		SysCallDataMap *ebpf.Map `ebpf:"sc_data"`
	}{}

	if err := sharedSpec.LoadAndAssign(&sharedObjs, nil); err != nil {
		log.Fatalf("Error loading shared objects: %v", err)
	}

	var scDataMap = sharedObjs.SysCallDataMap

	defer scDataMap.Close()

	// load tracepoint programs
	tpProgSpec, err := ebpf.LoadCollectionSpec("kprog/obj/tp/strace.bpf.o")
	if err != nil {
		log.Fatalf("Error reading ebpf program file: %v", err)
	}

	tpProgObjs := TracepointsObjs{}

	err = tpProgSpec.LoadAndAssign(&tpProgObjs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"sc_data": scDataMap,
		},
	})
	if err != nil {
		log.Fatalf("Error loading ebpf strace program: %v", err)
	}

	// load syscall parser programs
	dir, err := fs.ReadDir(bstrace.BpfObjFS, "kprog/obj/parser")
	if err != nil {
		log.Fatalf("Error reading ebpf program directory: %v", err)
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

		spec, err := ebpf.LoadCollectionSpec("kprog/obj/parser/" + d.Name())
		if err != nil {
			log.Fatalf("Error reading ebpf program file: %v", err)
		}

		parserCollection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
			MapReplacements: map[string]*ebpf.Map{
				"sc_data": scDataMap,
			},
		})
		if err != nil {
			log.Fatalf("Error loading parser collection %s: %v", parserCollection, err)
		}

		parserCollections = append(parserCollections, parserCollection)

		for name, program := range parserCollection.Programs {
			var syscallNR uint32

			for scName, v := range parserCollection.Variables {
				if scName == "SC_NR" {
					if err := v.Get(&syscallNR); err != nil {
						log.Fatalf("Error read %s variable for func %s: %v; var spec: %v", scName, name, err, parserCollection.Variables)
					}
					break
				}

				log.Printf("Not found variable '%s' for func %s; available var: %v", scName, name, parserCollection.Variables)
			}

			err = tpProgObjs.ProgMap.Put(syscallNR, program)
			if err != nil {
				log.Fatalf("Error putting program %s to map: %v", name, err)
			}

			log.Printf("Store program syscall %d from %s to prog array", syscallNR, name)
		}
	}

	return tpProgObjs, nil
}
