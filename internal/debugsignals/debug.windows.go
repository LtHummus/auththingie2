//go:build windows

package debugsignals

func ListenEnableDebugPage(stop <-chan struct{}) bool {
	// nop
	return false
}

func ListenEnableDebugLogging(stop <-chan struct{}) bool {
	// nop
	return false
}
