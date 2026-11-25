//go:build wasip1

package catalog

import (
	"errors"
	"unsafe"
)

//go:wasmimport wasi_snapshot_preview1 random_get
func wasiRandomGet(buf unsafe.Pointer, bufLen uint32) uint32

func fillCatalogRandomBytes(dst []byte) error {
	if len(dst) == 0 {
		return nil
	}
	errno := wasiRandomGet(unsafe.Pointer(&dst[0]), uint32(len(dst)))
	if errno != 0 {
		return errors.New("wasi random_get failed")
	}
	return nil
}
