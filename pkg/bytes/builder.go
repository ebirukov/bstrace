package bytes

import (
	"encoding/binary"
	"unsafe"
)

type Builder struct {
	buf []byte
}

func (bw *Builder) WriteUint64(order binary.AppendByteOrder, v uint64) *Builder {
	bw.buf = order.AppendUint64(bw.buf, v)

	return bw
}

func (bw *Builder) WriteInt64(order binary.AppendByteOrder, v int64) *Builder {
	bw.buf = order.AppendUint64(bw.buf, uint64(v))

	return bw
}

func (bw *Builder) WriteUint32(order binary.AppendByteOrder, v uint32) *Builder {
	bw.buf = order.AppendUint32(bw.buf, v)

	return bw
}

func (bw *Builder) WriteInt32(order binary.AppendByteOrder, v int32) *Builder {
	bw.buf = order.AppendUint32(bw.buf, uint32(v))

	return bw
}

func (bw *Builder) WritePointer(order binary.AppendByteOrder, v unsafe.Pointer) *Builder {
	bw.buf = order.AppendUint64(bw.buf, uint64(uintptr(v)))

	return bw
}

func (bw *Builder) Reset() *Builder {
	bw.buf = bw.buf[:0]

	return bw
}

func (bw *Builder) Bytes() []byte {
	return bw.buf
}
