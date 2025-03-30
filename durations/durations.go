package durations

import (
	"fmt"
	"strings"
	"time"
)

func NiceDuration(dur time.Duration) string {
	var sb strings.Builder

	written := false

	if dur >= 24*time.Hour {
		d := int(dur.Hours() / 24)
		dur -= time.Duration(d) * 24 * time.Hour

		u := "days"
		if d == 1 {
			u = "day"
		}

		sb.WriteString(fmt.Sprintf("%d %s", d, u))
		written = true
	}

	if dur >= 1*time.Hour {
		h := int(dur.Hours())
		dur -= time.Duration(h) * time.Hour

		u := "hours"
		if h == 1 {
			u = "hour"
		}

		spacer := ""
		if written {
			spacer = " "
		}

		sb.WriteString(fmt.Sprintf("%s%d %s", spacer, h, u))
		written = true
	}

	if dur >= 1*time.Minute {
		m := int(dur.Minutes())
		dur -= time.Duration(m) * time.Minute

		u := "minutes"
		if m == 1 {
			u = "minute"
		}
		spacer := ""
		if written {
			spacer = " "
		}

		sb.WriteString(fmt.Sprintf("%s%d %s", spacer, m, u))
		written = true
	}

	if dur > 0 || (!written && dur == 0) {
		spacer := ""
		if written {
			spacer = " "
		}

		u := "seconds"
		if dur == 1*time.Second {
			u = "second"
		}

		sb.WriteString(fmt.Sprintf("%s%.2g %s", spacer, dur.Seconds(), u))
	}

	return sb.String()
}
