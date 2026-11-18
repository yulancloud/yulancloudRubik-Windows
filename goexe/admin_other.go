//go:build !windows

package main

// 非 Windows 平台（仅供本地联调测试）：没有真正的管理员概念，
// 一律返回 true，由 dry-run 流程自测。
func isAdminRuntime() bool {
	return true
}
