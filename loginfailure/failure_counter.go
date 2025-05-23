package loginfailure

type Counter interface {
	LoginsRemaining(username string) int
	IsUserLocked(username string) bool
	RecordFailure(username string)
	ClearFailures(username string)
}
