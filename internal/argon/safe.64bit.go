//go:build amd64 || arm64 || mips64 || mips64le || ppc64 || ppc64le || riscv64

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

	if x > math.MaxUint32 {
		return 0, fmt.Errorf("argon2: can not cast %d to uint32", x)
	}

	return uint32(x), nil
}
