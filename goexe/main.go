// =====================================================================
// 欲蓝财务魔方 APP（Go 版，编译为单个 exe，无需任何运行环境）
//
// 功能与 Python 版完全一致：
//   - 只能在 Windows 管理员账号下运行（非管理员直接退出）
//   - 日志写入 logs/yulan_cube.log，并用 icacls 锁死 ACL：
//     只有 SYSTEM 与 Administrators 可访问，其他用户完全不可见
//   - 监听 HTTP 端口，Bearer Token 鉴权
//   - POST /api/v1/create-user：按 APP 配置决定普通/管理员角色，
//     执行 net user / net localgroup 建号命令
//   - POST /api/v1/update-user：以管理员权限强制修改已建账号
//     改密码：net user 账号 新密码        （不需旧密码）
//     改用户名：Rename-LocalUser          （可切 wmic 兼容老系统）
//   - 日志一律脱敏：密码显示为 ***
//
// 命令契约（与网站端 YulanConnector 对接）：
//
//	普通： net user 用户名 密码 /add
//	管理员：再加 net localgroup administrators 用户名 /add
//	两种都要： net localgroup "Remote Desktop Users" 用户名 /add
//
// =====================================================================
package main

import (
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

const appVersion = "1.2.1"

// ---------------- 配置 ----------------

type Config struct {
	ListenHost    string   `json:"listen_host"`
	ListenPort    int      `json:"listen_port"`
	Token         string   `json:"token"`
	DefaultRole   string   `json:"default_role"`
	AdminProducts []string `json:"admin_products"`
	AdminGroup    string   `json:"admin_group_name"`
	RDPGroup      string   `json:"rdp_group_name"`
	ServerIP      string   `json:"server_ip"`
	UsePowerShell bool     `json:"use_powershell"`
	RenameMethod  string   `json:"rename_method"` // powershell / wmic
}

func loadConfig(path string) *Config {
	cfg := &Config{
		ListenHost:   "127.0.0.1",
		ListenPort:   8321,
		DefaultRole:  "user",
		AdminGroup:   "administrators",
		RDPGroup:     "Remote Desktop Users",
		RenameMethod: "powershell",
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[配置] 读取 %s 失败：%v，使用默认值。\n", path, err)
		return cfg
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "[配置] 解析 %s 失败：%v，使用默认值。\n", path, err)
	}
	if cfg.RenameMethod == "" {
		cfg.RenameMethod = "powershell"
	}
	return cfg
}

func defaultConfigSample() []byte {
	sample := map[string]any{
		"listen_host":      "0.0.0.0",
		"listen_port":      8321,
		"token":            "请改成一段足够长的随机口令，与网站后台「欲蓝服务器」里填的口令一致",
		"default_role":     "user",
		"admin_products":   []string{"填入走管理员角色的商品ID"},
		"admin_group_name": "administrators",
		"rdp_group_name":   "Remote Desktop Users",
		"server_ip":        "填本机对外 IP，仅作备注",
		"use_powershell":   false,
		"rename_method":    "powershell",
	}
	b, _ := json.MarshalIndent(sample, "", "  ")
	return b
}

// ---------------- 日志（脱敏 + ACL 隔离） ----------------

type AppLogger struct {
	mu sync.Mutex
	f  *os.File
}

var accountRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,20}$`)
var secureStringRe = regexp.MustCompile(`ConvertTo-SecureString '[^']*'`)

func (lg *AppLogger) write(level, msg string) {
	line := fmt.Sprintf("[%s] [%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), level, msg)
	lg.mu.Lock()
	defer lg.mu.Unlock()
	if lg.f != nil {
		lg.f.WriteString(line)
	}
	fmt.Fprint(os.Stderr, line)
}

// maskNetArgs 生成用于日志的脱敏命令串，覆盖三种含口令的情况：
//   - net user 账号 密码 /add   （建号）
//   - net user 账号 新密码      （改密，4 参数，索引 3 是密码）
//   - PowerShell ConvertTo-SecureString '密码'（脚本内明文）
func maskNetArgs(args []string) string {
	out := make([]string, len(args))
	copy(out, args)
	if len(out) >= 4 && strings.EqualFold(out[0], "net") && strings.EqualFold(out[1], "user") {
		out[3] = "***"
	}
	for i := range out {
		out[i] = secureStringRe.ReplaceAllString(out[i], "ConvertTo-SecureString '***'")
	}
	return strings.Join(out, " ")
}

func secureLogDir(dir string, lg *AppLogger) {
	if runtime.GOOS != "windows" {
		return
	}
	// 1) 去掉继承  2) 只授予 SYSTEM 与 Administrators 完全控制
	// （S-1-5-18 = SYSTEM，S-1-5-32-544 = Administrators）
	steps := [][]string{
		{"icacls", dir, "/inheritance:r"},
		{"icacls", dir, "/grant:r", "*S-1-5-18:(OI)(CI)F"},
		{"icacls", dir, "/grant:r", "*S-1-5-32-544:(OI)(CI)F"},
	}
	for _, args := range steps {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			lg.write("WARN", fmt.Sprintf("ACL 设置命令失败：%v：%s", err, strings.TrimSpace(string(out))))
		}
	}
	lg.write("INFO", "日志目录 ACL 已加固：仅 SYSTEM 与 Administrators 可访问，其他用户完全不可见")
}

// ---------------- 管理员门禁（平台相关，见 admin_windows.go / admin_other.go） ----------------

// ---------------- HTTP 服务 ----------------

type createUserReq struct {
	OrderNo   string `json:"order_no"`
	ProductID string `json:"product_id"`
	Account   string `json:"account"`
	Password  string `json:"password"`
}

type updateUserReq struct {
	OrderNo     string `json:"order_no"`
	Account     string `json:"account"`      // 当前账号名（旧名）
	NewAccount  string `json:"new_account"`  // 新账号名（可选）
	NewPassword string `json:"new_password"` // 新密码（可选）
}

type updateResult struct {
	PasswordChanged bool
	Renamed         bool
	FinalAccount    string
	Detail          string
}

type Server struct {
	cfg    *Config
	logger *AppLogger
	dryRun bool
}

func (s *Server) decideRole(productID string) string {
	for _, id := range s.cfg.AdminProducts {
		if strings.EqualFold(strings.TrimSpace(id), productID) {
			return "admin"
		}
	}
	return s.cfg.DefaultRole
}

func (s *Server) runCmd(name string, args ...string) (int, string, error) {
	all := append([]string{name}, args...)
	if s.dryRun {
		s.logger.write("INFO", "[DRY-RUN] 将执行："+maskNetArgs(all))
		return 0, "[dry-run] 未真正执行", nil
	}
	s.logger.write("INFO", "执行命令："+maskNetArgs(all))
	out, err := exec.Command(name, args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return 1, text, err
	}
	return 0, text, nil
}

// authOK 恒定时间比较 Bearer Token，防时序侧信道
func (s *Server) authOK(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	return len(auth) > len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) &&
		subtle.ConstantTimeCompare([]byte(auth[len(prefix):]), []byte(s.cfg.Token)) == 1
}

func readBody(r *http.Request) []byte {
	body := make([]byte, 65536)
	n, _ := r.Body.Read(body)
	return body[:n]
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		s.logger.write("WARN", "鉴权失败：Token 无效，已拒绝请求")
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "unauthorized"})
		return
	}

	var req createUserReq
	if err := json.Unmarshal(readBody(r), &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid_json"})
		return
	}

	if !accountRe.MatchString(req.Account) {
		s.logger.write("WARN", fmt.Sprintf("拒绝建号：账号名非法（订单 %s）", req.OrderNo))
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid_account"})
		return
	}
	if len(req.Password) < 6 {
		s.logger.write("WARN", fmt.Sprintf("拒绝建号：密码太短（订单 %s，账号 %s）", req.OrderNo, req.Account))
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "weak_password"})
		return
	}

	role := s.decideRole(req.ProductID)
	s.logger.write("INFO", fmt.Sprintf("收到建号请求：订单 %s，商品 %s，账号 %s，角色=%s（由 APP 决定）",
		req.OrderNo, req.ProductID, req.Account, role))

	var detailParts []string
	failed := false

	// 1) net user 账号 密码 /add
	if rc, out, err := s.runCmd("net", "user", req.Account, req.Password, "/add"); rc != 0 || err != nil {
		s.logger.write("ERROR", fmt.Sprintf("创建账号失败：账号 %s：%s %v", req.Account, out, err))
		detailParts = append(detailParts, "创建账号失败："+out)
		failed = true
	} else {
		detailParts = append(detailParts, "创建账号成功："+firstLine(out))
	}

	// 2) 管理员角色：net localgroup administrators 账号 /add
	if !failed && role == "admin" {
		if rc, out, err := s.runCmd("net", "localgroup", s.cfg.AdminGroup, req.Account, "/add"); rc != 0 || err != nil {
			s.logger.write("ERROR", fmt.Sprintf("加入管理员组失败：账号 %s：%s %v", req.Account, out, err))
			detailParts = append(detailParts, "加入管理员组失败："+out)
			failed = true
		} else {
			detailParts = append(detailParts, "已加入管理员组："+firstLine(out))
		}
	}

	// 3) 无论普通还是管理员：加入 Remote Desktop Users（允许远程桌面登录）
	if !failed {
		if rc, out, err := s.runCmd("net", "localgroup", s.cfg.RDPGroup, req.Account, "/add"); rc != 0 || err != nil {
			s.logger.write("ERROR", fmt.Sprintf("加入远程桌面组失败：账号 %s：%s %v", req.Account, out, err))
			detailParts = append(detailParts, "加入远程桌面组失败："+out)
			failed = true
		} else {
			detailParts = append(detailParts, "已加入远程桌面组："+firstLine(out))
		}
	}

	if failed {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "role": role, "detail": strings.Join(detailParts, "；")})
		return
	}
	s.logger.write("INFO", fmt.Sprintf("建号完成：账号 %s，角色 %s", req.Account, role))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "role": role, "detail": strings.Join(detailParts, "；")})
}

// handleUpdateUser 以管理员权限强制修改已建账号（网站「控制台 / 商品详情」调用）。
// 顺序：先改密（用旧名），再改名 —— 改名后旧登录名即失效。
func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		s.logger.write("WARN", "改号鉴权失败：Token 无效，已拒绝请求")
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "unauthorized"})
		return
	}

	var req updateUserReq
	if err := json.Unmarshal(readBody(r), &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid_json"})
		return
	}

	res := updateResult{FinalAccount: req.Account}

	// ---- 参数校验 ----
	if !accountRe.MatchString(req.Account) {
		writeJSON(w, http.StatusOK, s.failUpdate(res, "原账号名不合法"))
		return
	}
	if req.NewAccount == "" && req.NewPassword == "" {
		writeJSON(w, http.StatusOK, s.failUpdate(res, "没有需要修改的内容（请提供新账号名或新密码）"))
		return
	}
	if req.NewAccount != "" && req.NewAccount == req.Account {
		writeJSON(w, http.StatusOK, s.failUpdate(res, "新账号名与原账号名相同，无需修改"))
		return
	}
	if req.NewAccount != "" && !accountRe.MatchString(req.NewAccount) {
		writeJSON(w, http.StatusOK, s.failUpdate(res, "新账号名不合法（仅允许 1-20 位字母数字及 . _ -）"))
		return
	}
	if req.NewPassword != "" && len(req.NewPassword) < 6 {
		writeJSON(w, http.StatusOK, s.failUpdate(res, "新密码长度不足（至少 6 位）"))
		return
	}

	s.logger.write("INFO", fmt.Sprintf(
		"收到改号请求：订单 %s，账号 %s，改用户名=%v，改密码=%v",
		req.OrderNo, req.Account, req.NewAccount != "", req.NewPassword != ""))

	var details []string

	// 1) 改密码：net user 账号 新密码（不带 /add，管理员强制重置，不需旧密码）
	if req.NewPassword != "" {
		var rc int
		var out string
		var err error
		if s.cfg.UsePowerShell {
			script := fmt.Sprintf("$pw = ConvertTo-SecureString '%s' -AsPlainText -Force; "+
				"Set-LocalUser -Name '%s' -Password $pw -ErrorAction Stop; exit 0",
				req.NewPassword, req.Account)
			rc, out, err = s.runCmd("powershell", "-NoProfile", "-Command", script)
		} else {
			rc, out, err = s.runCmd("net", "user", req.Account, req.NewPassword)
		}
		if rc != 0 || err != nil {
			s.logger.write("ERROR", fmt.Sprintf("改密码失败：账号 %s：%s %v", req.Account, out, err))
			writeJSON(w, http.StatusOK, s.failUpdate(res, "改密码失败："+out))
			return
		}
		res.PasswordChanged = true
		details = append(details, "密码已重置")
	}

	// 2) 改用户名：Rename-LocalUser（SID 不变，管理员组/远程桌面组关系保留）
	if req.NewAccount != "" {
		var rc int
		var out string
		var err error
		if strings.EqualFold(s.cfg.RenameMethod, "wmic") {
			// 兼容未安装 PowerShell LocalAccounts 模块的老系统
			rc, out, err = s.runCmd("wmic", "useraccount", "where", "name='"+req.Account+"'",
				"call", "Rename", req.NewAccount)
		} else {
			script := fmt.Sprintf("Rename-LocalUser -Name '%s' -NewName '%s' -ErrorAction Stop; exit 0",
				req.Account, req.NewAccount)
			rc, out, err = s.runCmd("powershell", "-NoProfile", "-Command", script)
		}
		if rc != 0 || err != nil {
			s.logger.write("ERROR", fmt.Sprintf("改用户名失败：账号 %s：%s %v", req.Account, out, err))
			tail := ""
			if res.PasswordChanged {
				tail = "（密码修改已生效）"
			}
			writeJSON(w, http.StatusOK, s.failUpdate(res, "改用户名失败："+out+tail))
			return
		}
		res.Renamed = true
		res.FinalAccount = req.NewAccount
		details = append(details, "用户名已改为 "+req.NewAccount)
	}

	res.Detail = strings.Join(details, "；")
	if res.Detail == "" {
		res.Detail = "无修改"
	}
	s.logger.write("INFO", fmt.Sprintf("改号完成：账号 %s，改密=%v，改名=%v",
		res.FinalAccount, res.PasswordChanged, res.Renamed))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "password_changed": res.PasswordChanged, "renamed": res.Renamed,
		"account": res.FinalAccount, "detail": res.Detail,
	})
}

func (s *Server) failUpdate(res updateResult, detail string) map[string]any {
	res.Detail = detail
	return map[string]any{
		"ok": false, "password_changed": res.PasswordChanged, "renamed": res.Renamed,
		"account": res.FinalAccount, "detail": res.Detail,
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "service": "yulan-cube-app", "version": appVersion,
			"capabilities":  []string{"create-user", "update-user"},
			"role_decision": "app", "server_ip": s.cfg.ServerIP,
		})
	})
	mux.HandleFunc("/api/v1/create-user", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method_not_allowed"})
			return
		}
		s.handleCreateUser(w, r)
	})
	mux.HandleFunc("/api/v1/update-user", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method_not_allowed"})
			return
		}
		s.handleUpdateUser(w, r)
	})
	return logRequest(mux, s.logger)
}

func logRequest(next http.Handler, lg *AppLogger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lg.write("INFO", fmt.Sprintf("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr))
		next.ServeHTTP(w, r)
	})
}

func main() {
	exePath, _ := os.Executable()
	baseDir := filepath.Dir(exePath)

	cfgPath := flag.String("config", filepath.Join(baseDir, "yulan_cube_config.json"), "配置文件路径")
	allowNonAdmin := flag.Bool("allow-non-admin", false, "允许非管理员运行（仅测试用，Windows 上请勿使用）")
	dryRun := flag.Bool("dry-run", false, "只打印将执行的命令，不真正执行（测试用）")
	flag.Parse()

	fmt.Printf("欲蓝财务魔方 APP v%s（Go 版单文件，无需任何运行环境）\n", appVersion)

	// ---- 管理员门禁：Windows 下必须是管理员账号启动 ----
	// 判定逻辑见 admin_windows.go：同时接受「UAC 提权令牌」与「管理员组成员身份」，
	// 与 Python 版 IsUserAnAdmin 行为一致，避免域账号 / runas / 计划任务等场景误判。
	if !isAdminRuntime() && !*allowNonAdmin {
		msg := "本 APP 只能在管理员账号下运行。\n\n" +
			"当前账号未被识别为管理员，请任选一种方式启动：\n" +
			"  1) 右键本 exe →「以管理员身份运行」\n" +
			"  2) 双击 run_as_admin.bat（会自动请求提权）\n" +
			"  3) 用计划任务勾选「使用最高权限运行」启动\n\n" +
			"如果你确认自己用的是管理员账号仍提示此错误，\n" +
			"可在命令行加 --allow-non-admin 参数临时跳过检查（仅限排查）。"
		fmt.Fprintln(os.Stderr, "❌ "+msg)
		os.Exit(2)
	}
	if isAdminRuntime() {
		fmt.Println("✓ 管理员权限确认")
	}

	// ---- 日志初始化（目录 + ACL 加固） ----
	logDir := filepath.Join(baseDir, "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "创建日志目录失败：%v\n", err)
		os.Exit(1)
	}
	lg := &AppLogger{}
	logFile := filepath.Join(logDir, "yulan_cube.log")
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "打开日志文件失败：%v\n", err)
		os.Exit(1)
	}
	lg.f = f
	secureLogDir(logDir, lg)
	log.SetOutput(lg.f)

	// ---- 配置 ----
	cfg := loadConfig(*cfgPath)
	if cfg.Token == "" || strings.Contains(cfg.Token, " ") ||
		strings.HasPrefix(cfg.Token, "请改成") {
		fmt.Fprintln(os.Stderr, "❌ 配置文件里的 token 为空或仍是占位值，请先编辑配置再启动。")
		os.Exit(1)
	}
	if *dryRun {
		lg.write("INFO", "DRY-RUN 模式：所有命令只打印不执行")
	}
	srv := &Server{cfg: cfg, logger: lg, dryRun: *dryRun}

	lg.write("INFO", fmt.Sprintf("欲蓝财务魔方 APP v%s 启动：监听 %s:%d，默认角色=%s，管理员商品 %d 个",
		appVersion, cfg.ListenHost, cfg.ListenPort, cfg.DefaultRole, len(cfg.AdminProducts)))

	addr := fmt.Sprintf("%s:%d", cfg.ListenHost, cfg.ListenPort)
	fmt.Printf("✓ 监听 http://%s  （健康检查：/api/v1/health）\n", addr)
	fmt.Println("✓ 已开启建号 /api/v1/create-user 与改号 /api/v1/update-user")
	fmt.Println("✓ 日志：" + logFile + "（已 ACL 隔离，普通用户不可见）")
	if err := http.ListenAndServe(addr, srv.routes()); err != nil {
		lg.write("ERROR", "HTTP 服务退出："+err.Error())
		fmt.Fprintln(os.Stderr, "HTTP 服务退出：", err)
		os.Exit(1)
	}
}
