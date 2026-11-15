//go:build windows

package main

import (
	"golang.org/x/sys/windows"
)

// isAdminRuntime 检查当前进程是否以 Windows 管理员身份运行
func isAdminRuntime() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}
