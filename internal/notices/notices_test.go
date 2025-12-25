package notices

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddMessage(t *testing.T) {
	t.Cleanup(func() {
		Reset()
	})

	assert.Empty(t, GetMessages())

	AddMessage("foo", "hello world")
	assert.Len(t, GetMessages(), 1)

	AddMessage("bar", "hello world 2")
	assert.Len(t, GetMessages(), 2)

	msgs := GetMessages()

	assert.Len(t, msgs, 2)

	assert.Contains(t, msgs, "hello world")
	assert.Contains(t, msgs, "hello world 2")

	// make sure duplicate message IDs don't get added
	AddMessage("foo", "hello world")
	assert.Len(t, GetMessages(), 2)

	// make sure messages can not be mutated from outside
	msgs = append(msgs, "this should not be here")
	assert.Len(t, GetMessages(), 2)
}

func TestDeleteMessage(t *testing.T) {
	t.Cleanup(func() {
		Reset()
	})

	assert.Empty(t, GetMessages())

	AddMessage("a", "hello")
	assert.Len(t, GetMessages(), 1)

	// make sure you can delete non-existing messages quietly
	DeleteMessage("b")
	assert.Len(t, GetMessages(), 1)

	AddMessage("b", "hello2")
	assert.Len(t, GetMessages(), 2)

	DeleteMessage("b")
	assert.Len(t, GetMessages(), 1)

	DeleteMessage("a")
	assert.Len(t, GetMessages(), 0)
}

func TestReset(t *testing.T) {
	t.Cleanup(func() {
		Reset()
	})

	assert.Empty(t, GetMessages())
	AddMessage("a", "a")
	AddMessage("b", "b")
	AddMessage("c", "c")

	assert.Len(t, GetMessages(), 3)

	Reset()

	assert.Len(t, GetMessages(), 0)
}
