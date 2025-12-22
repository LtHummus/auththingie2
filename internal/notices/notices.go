package notices

import "sync"

var (
	notices     []string
	noticeIDs   = map[string]struct{}{}
	noticesLock = sync.Mutex{}
)

func AddMessage(id string, message string) {
	noticesLock.Lock()
	defer noticesLock.Unlock()
	if _, exists := noticeIDs[id]; exists {
		return
	}

	noticeIDs[id] = struct{}{}
	notices = append(notices, message)
}

func GetMessages() []string {
	noticesLock.Lock()
	defer noticesLock.Unlock()

	ret := make([]string, len(notices))
	copy(ret, notices)
	return ret
}

func Reset() {
	noticesLock.Lock()
	defer noticesLock.Unlock()

	notices = nil
	noticeIDs = map[string]struct{}{}
}
