package bstrace

import "embed"

//go:embed kprog/obj/**
var BpfObjFS embed.FS
