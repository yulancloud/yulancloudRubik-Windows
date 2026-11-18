//go:build windows

package main

import (
	"golang.org/x/sys/windows"
)

// hasAdminPrivilege 判断当前访问令牌是否具备管理员权限。
//
// 为什么不只用 IsElevated()：
//
//	IsElevated() 查询的是 UAC「提升令牌」。在域账户、runas 启动、计划任务
//	（最高权限运行）、关闭 UAC、内置 Administrator 等场景下，用户账号确实是
//	管理员，但进程令牌没有走 UAC 提权流程，IsElevated() 会错误地返回 false，
//	导致旧版 Go APP 一启动就判定「不是管理员」而闪退；而同机的 Python 版用
//	shell32.IsUserAnAdmin()（底层 CheckTokenMembership）判定正常可用。
//
// 这里改成多重判定，任一命中即认为有管理员权限（与 Python 客户端行为对齐）：
//  1. token.IsElevated()                    —— 标准 UAC 提权令牌
//  2. token.IsMember(Administrators)         —— 管理员组的启用成员
//  3. TokenGroups 中出现 Administrators SID  —— 账号属于管理员组（含未提权/deny-only）
func hasAdminPrivilege(token windows.Token) bool {
	// 1) UAC 提升令牌
	if token.IsElevated() {
		return true
	}

	adminSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}

	// 2) 管理员组启用成员（等价于 Python 版 IsUserAnAdmin 的底层检查）
	if ok, err := token.IsMember(adminSid); err == nil && ok {
		return true
	}

	// 3) 遍历令牌组，只要出现管理员 SID 即认为该账号是管理员
	//    （覆盖 UAC 开启但未提权时 Administrators 组为 deny-only 的场景）
	groups, err := token.GetTokenGroups()
	if err != nil || groups == nil {
		return false
	}
	for _, g := range groups.AllGroups() {
		if g.Sid != nil && g.Sid.Equals(adminSid) {
			return true
		}
	}
	return false
}

// isAdminRuntime 检查当前进程是否具备管理员权限。
func isAdminRuntime() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	return hasAdminPrivilege(token)
}
