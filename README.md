# 欲蓝财务魔方 APP（Windows 服务端）

网站下单后，由本程序在 Windows 服务器上创建 Windows 账号；用户在网站「控制台」修改用户名/密码时，也由本程序以管理员权限强制修改。
**推荐使用单文件版 `yulan_cube_app.exe`——不需要安装 Python，也不需要任何运行环境，拷过去就能跑。**

## 文件清单

| 文件 | 说明 |
|---|---|
| `yulan_cube_app.exe` | 主程序（Go 编译的单文件 exe，约 6.7MB，无需任何环境） |
| `yulan_cube_config.json` | 配置文件（启动时读取） |
| `run_as_admin.bat` | 双击以管理员身份启动（自动弹 UAC 提权） |
| `README.md` | 本说明 |
| `yulan_cube_app.py` | Python 源码版（备用，与 exe 功能一致） |
| `goexe/` | exe 的 Go 源码（想自己重新编译才需要） |

## 部署步骤（3 步）

1. 把整个 `windows_app` 文件夹拷到 Windows 服务器，例如 `D:\yulan_app\`
2. 编辑 `yulan_cube_config.json`：
   - `token`：改成一段随机口令（至少 6 位），必须与网站后台「欲蓝服务器」里填的**口令**完全一致
   - `listen_port`：监听端口，默认 `8321`（网站后台也要填同一个）
   - `admin_products`：填**走管理员角色**的商品 ID（数组）；不在名单里的商品一律创建普通用户
   - `listen_host`：网站从外网访问本机就填 `0.0.0.0`（默认）；只允许本机调试填 `127.0.0.1`
3. 双击 `run_as_admin.bat` 启动（或右键 exe → 以管理员身份运行）

防火墙放行 8321 端口入站。然后在网站后台「欲蓝服务器」里填 Windows 服务器 IP、端口、口令即可。

## 安全机制（按需求实现）

- **只能在管理员账号下运行**：非管理员启动直接退出；`run_as_admin.bat` 会自动请求提权
- **其他用户完全看不到运行日志**：日志写入 `logs\yulan_cube.log`，启动时自动用 `icacls` 锁死目录 ACL——只有 SYSTEM 和 Administrators 有权限，普通用户连读取都不行
- **日志不泄露密码**：`net user 账号 *** /add`，密码、Token 一律脱敏为 `***`
- **Bearer Token 鉴权**：网站请求必须带与配置一致的口令，否则 401 拒绝

## 建号命令契约

收到网站请求后，**APP 决定**该账号是普通用户还是管理员（看 `admin_products` 名单）：

- 所有账号：`net user 账号 密码 /add`
- 管理员账号再执行：`net localgroup administrators 账号 /add`
- 无论哪种都会执行：`net localgroup "Remote Desktop Users" 账号 /add`（允许远程桌面登录）

返回 `{"ok": true, "role": "user"|"admin", "detail": "..."}` 给网站。

## 改号命令契约（v1.2 新增 · 用户中心「控制台」）

用户在网站「用户中心 → 控制台 → 商品详情」里修改**登录用户名 / 密码**时，网站把命令发给本 APP，由 APP **以管理员权限强制修改**（网站不存储密码，所以改密一律是「管理员强制重置」，无需旧密码）：

| 操作 | 命令 | 说明 |
|---|---|---|
| 改密码 | `net user 账号 新密码` | 不带 `/add`，管理员强制重置；不需要也不校验旧密码 |
| 改用户名 | `Rename-LocalUser -Name '旧' -NewName '新'` | `net user` 不支持改名；用 PowerShell，SID 不变，管理员组 / 远程桌面组关系保留 |
| 老系统兼容 | `wmic useraccount where "name='旧'" call Rename "新"` | 配置 `rename_method: "wmic"` 时启用（未装 PowerShell LocalAccounts 模块的老系统） |

- 接口：`POST /api/v1/update-user`，同样要 `Authorization: Bearer {token}`
- 请求：`{"order_no":"...","account":"旧名","new_account":"新名(可选)","new_password":"新密码(可选)"}`，两项至少一个非空
- 响应：`{"ok":true,"password_changed":bool,"renamed":bool,"account":"最终账号名","detail":"..."}`
- 顺序：**先改密（用旧名）、再改名**；改名后旧登录名即失效
- 开启 `use_powershell: true` 时改密走 `Set-LocalUser` + `SecureString`（口令不进进程参数）
- 日志一律脱敏：改密命令打印为 `net user 账号 ***`，PowerShell 脚本里的口令打印为 `***`

> 健康检查 `/api/v1/health` 的 `capabilities` 会包含 `["create-user","update-user"]`，可据此判断 APP 是否已升级到支持改号的版本。

## 长期驻留（推荐）

双击 bat 启动会开一个控制台窗口，关掉窗口程序就停了。长期运行建议二选一：

1. **计划任务**：任务计划程序 → 创建任务 → 「不管用户是否登录都要运行」+「使用最高权限运行」→ 操作填 exe 路径
2. **NSSM 注册为服务**：`nssm install YulanCube D:\yulan_app\yulan_cube_app.exe`

## 测试命令（可选）

启动时加参数 `--dry-run` 只打印将执行的命令、不真正建号，方便联调：

```bat
yulan_cube_app.exe --config yulan_cube_config.json --dry-run
```

健康检查：浏览器访问 `http://本机IP:8321/api/v1/health`，返回 `"ok": true` 即正常。

## 网站后台对应配置

| 网站后台「欲蓝服务器」 | APP 配置 |
|---|---|
| 服务器 IP | Windows 服务器对外 IP |
| 端口 | `listen_port`（默认 8321） |
| 口令 | `token`（两边必须一致） |
| 连接地址（RDP） | `server_ip` 仅作备注；网站后台的「连接地址」才是用户订单里显示的远程桌面地址 |

> 每个欲蓝商品还可以在网站后台单独配置自己的服务器（IP/端口/口令/连接地址），留空则用全局默认——对应 APP 无需改动，只要那台服务器上也跑着一个 APP 实例即可。
