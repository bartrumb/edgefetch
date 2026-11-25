//go:build !wasip1

package catalog

import "crypto/rand"

func fillCatalogRandomBytes(dst []byte) error {
	_, err := rand.Read(dst)
	return err
}
