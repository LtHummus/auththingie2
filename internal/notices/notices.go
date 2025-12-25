package notices

import "sync"

var (
	notices     = map[string]string{}
	noticesLock = sync.RWMutex{}
)

func AddMessage(id string, message string) {
	noticesLock.Lock()
	defer noticesLock.Unlock()
	if _, exists := notices[id]; exists {
		return
	}

	notices[id] = message
}

func DeleteMessage(id string) {
	noticesLock.Lock()
	defer noticesLock.Unlock()

	delete(notices, id)
}

func GetMessages() []string {
	noticesLock.RLock()
	defer noticesLock.RUnlock()

	ret := make([]string, len(notices))
	i := 0
	for _, msg := range notices {
		ret[i] = msg
		i++
	}

	return ret
}

func Reset() {
	noticesLock.Lock()
	defer noticesLock.Unlock()

	notices = map[string]string{}
}
