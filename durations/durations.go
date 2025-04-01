package durations

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

func appendAmount(sb *strings.Builder, amt int, unitName string, written bool) {
	if written {
		sb.WriteString(" ")
	}

	sb.WriteString(strconv.Itoa(amt))
	sb.WriteString(" ")
	sb.WriteString(unitName)
	if amt != 1 {
		sb.WriteString("s")
	}
}

func NiceDuration(dur time.Duration) string {
	var sb strings.Builder

	written := false

	if dur >= 24*time.Hour {
		d := int(dur.Hours() / 24)
		dur -= time.Duration(d) * 24 * time.Hour

		appendAmount(&sb, d, "day", written)
		written = true
	}

	if dur >= 1*time.Hour {
		h := int(dur.Hours())
		dur -= time.Duration(h) * time.Hour

		appendAmount(&sb, h, "hour", written)
		written = true
	}

	if dur >= 1*time.Minute {
		m := int(dur.Minutes())
		dur -= time.Duration(m) * time.Minute

		appendAmount(&sb, m, "minute", written)
		written = true
	}

	if dur > 0 || (!written && dur == 0) {
		// special case for remaining seconds
		if written {
			sb.WriteString(" ")
		}

		s := math.Trunc(dur.Seconds())

		// use sprintf here because we get better control of precision
		sb.WriteString(fmt.Sprintf("%.2g", s))
		sb.WriteString(" ")
		sb.WriteString("second")
		if s != 1 {
			sb.WriteString("s")
		}
	}

	return sb.String()
}
