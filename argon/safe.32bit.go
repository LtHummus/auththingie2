//go:build 386 || arm || mips || mipsle

package argon

import (
	"fmt"
	"math"
)

func safeCastUint8(x int) (uint8, error) {
	if x < 0 {
		return 0, fmt.Errorf("argon2: can not cast %d to uint8", x)
	}

	if x > math.MaxUint8 {
		return 0, fmt.Errorf("argon2: can not cast %d uint8", x)
	}

	return uint8(x), nil
}

func safeCastUint32(x int) (uint32, error) {
	if x < 0 {
		return 0, fmt.Errorf("argon2: can not cast %d to uint32", x)
	}

	// x (in an untyped int on a 32 bit system) can not possibly be larger than uint32

	return uint32(x), nil
}
