package durations

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNiceDuration(t *testing.T) {
	assert.Equal(t, "10 hours", NiceDuration(10*time.Hour))
	assert.Equal(t, "10 hours 5 minutes", NiceDuration(10*time.Hour+5*time.Minute))
	assert.Equal(t, "59 seconds", NiceDuration(59*time.Second))
	assert.Equal(t, "0.001 seconds", NiceDuration(1000*time.Microsecond))
	assert.Equal(t, "0 seconds", NiceDuration(0*time.Minute))
	assert.Equal(t, "20 hours 30 minutes 10 seconds", NiceDuration(20*time.Hour+30*time.Minute+10*time.Second))
	assert.Equal(t, "1 day 16 hours", NiceDuration(40*time.Hour))
	assert.Equal(t, "2 days", NiceDuration(48*time.Hour))
	assert.Equal(t, "2 days 10 hours", NiceDuration(58*time.Hour))
	assert.Equal(t, "2 days 10 hours 4 minutes 10 seconds", NiceDuration(58*time.Hour+4*time.Minute+10*time.Second))
	assert.Equal(t, "1.5 seconds", NiceDuration(1500*time.Millisecond))
	assert.Equal(t, "10 minutes", NiceDuration(10*time.Minute))
	assert.Equal(t, "1 minute", NiceDuration(60*time.Second))
	assert.Equal(t, "1 minute 1 second", NiceDuration(61*time.Second))
	assert.Equal(t, "1 day 1 hour 1 minute 1 second", NiceDuration(25*time.Hour+1*time.Minute+1*time.Second))
}
