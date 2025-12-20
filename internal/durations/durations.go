package durations

import (
	"fmt"
	"strings"
	"time"
)

type unit struct {
	name string
	val  time.Duration
}

var units = []unit{
	{"day", 24 * time.Hour},
	{"hour", time.Hour},
	{"minute", time.Minute},
	{"second", time.Second},
}

func NiceDuration(dur time.Duration) string {
	if dur == 0 {
		return "0 seconds"
	}

	var parts []string
	for _, curr := range units {
		if dur >= curr.val {
			amt := int(dur / curr.val)
			dur %= curr.val

			part := fmt.Sprintf("%d %s", amt, curr.name)
			if amt != 1 {
				part += "s"
			}
			parts = append(parts, part)
		}
	}

	if len(parts) == 0 {
		return "0 seconds"
	}

	return strings.Join(parts, " ")
}
