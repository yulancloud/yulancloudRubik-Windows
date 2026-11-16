#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
欲蓝财务魔方 —— Windows 服务端 APP（官方参考实现）
=================================================

本程序运行在客户购买的 Windows 服务器上，负责：
  1. 仅允许「管理员账号」运行；非管理员直接退出，且「不产生任何可被他人看到的日志」。
  2. 运行日志写入受 ACL（访问控制列表）严格保护的目录，仅 Administrators / SYSTEM
     可读写，其他（非管理员）用户完全无法查看（连目录列表都看不到）。
  3. 监听配置的端口（默认 8321），通过 Bearer Token 与网站后台鉴权。
  4. 收到建号请求后，由「本 APP 自己」决定该账号是「普通用户」还是「管理员」，
     并执行对应的 Windows 命令：
         - 普通用户：net user 用户名 密码 /add
         - 管理员：  额外执行 net localgroup administrators 用户名 /add
         - 两者都要：net localgroup "Remote Desktop Users" 用户名 /add
  5. 返回统一结果：{"ok": true/false, "role": "user"|"admin", "detail": "..."}
  6. 收到改号请求（用户在网站「控制台 / 商品详情」里修改）后，以管理员权限强制修改：
         - 改密码：net user 账号 新密码                    （不需旧密码，管理员强制重置）
         - 改用户名：Rename-LocalUser -Name '旧' -NewName '新'（可切 wmic 兼容老系统）
     改名不改 SID，管理员组 / 远程桌面组成员关系自动保留；网站端不存储密码，
     所以改密一律是「管理员强制重置」，无需也不校验旧密码。

安全基线（与网站端约定一致）：
  - 日志中【绝不】记录口令，也【绝不】记录鉴权 Token。
  - 口令仅在进程内临时使用，不落盘、不下发。
  - 仅依赖 Python 标准库，无需联网安装任何第三方包。

部署建议（满足「其他用户完全看不到运行日志」）：
  - 以「Windows 服务」或「计划任务（最高权限 / 不管用户是否登录都运行）」方式后台运行，
    不要在任何交互式用户桌面弹出可见窗口。
  - 配置文件（含 Token）放在受保护目录，权限同日志目录。

跨平台说明：
  - Windows 下走真实的 net / icacls 命令与 ACL 加固。
  - 非 Windows（如 Linux 本地联调）可用 --dry-run 模拟建号、用 --allow-non-admin
    跳过管理员检查，仅用于开发联调，切勿用于生产。
"""

import argparse
import base64
import ctypes
import datetime as _dt
import hmac
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# ----------------------------------------------------------------------------
# 常量
# ----------------------------------------------------------------------------
DEFAULT_PORT = 8321
DEFAULT_HOST = "0.0.0.0"
CONFIG_FILENAME = "yulan_cube_config.json"
APP_VERSION = "1.2.0"

# Windows 已知 SID
SID_SYSTEM = "S-1-5-18"          # SYSTEM
SID_ADMINISTRATORS = "S-1-5-32-544"  # Administrators 组
# 注：刻意【不】对任何“用户组”授权，从而自然屏蔽所有非管理员。

# 账号名规则（与网站端 YulanProvision::ACCOUNT_RE 保持一致）
ACCOUNT_RE_HINT = r"^[A-Za-z0-9._-]{1,20}$"


def _now_iso() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ----------------------------------------------------------------------------
# 1) 管理员身份检查
# ----------------------------------------------------------------------------
def is_running_as_admin() -> bool:
    """当前进程是否以管理员权限运行。非 Windows 环境返回 False（需配合 --allow-non-admin）。"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        # 非 Windows（Linux/macOS）没有该 API
        return False


def ensure_admin(allow_non_admin: bool) -> None:
    """非管理员则退出。allow_non_admin 仅用于本地联调。"""
    if is_running_as_admin():
        return
    if allow_non_admin:
        sys.stderr.write(
            "[警告] 当前不是管理员账号，但已通过 --allow-non-admin 跳过检查（仅限本地联调）。\n"
        )
        return
    sys.stderr.write(
        "【拒绝运行】欲蓝财务魔方 APP 必须且只能在「管理员账号」下运行。\n"
        "请右键本程序 →「以管理员身份运行」，或使用计划任务（最高权限）启动。\n"
    )
    sys.exit(1)


# ----------------------------------------------------------------------------
# 2) 日志目录与 ACL 加固（其他用户不可见）
# ----------------------------------------------------------------------------
def _harden_acl_windows(path: str) -> None:
    """用 icacls 去掉继承、仅授予 SYSTEM 与 Administrators 完全控制，从而屏蔽所有非管理员。"""
    # 去掉从父目录继承的 ACE（否则 Users 可能仍有读权限）
    subprocess.run(
        ["icacls", path, "/inheritance:r"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    # 仅授予 SYSTEM 与 Administrators（含子目录/文件）
    for sid in (SID_SYSTEM, SID_ADMINISTRATORS):
        subprocess.run(
            ["icacls", path, "/grant:r", f"*{sid}:(OI)(CI)F"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    # 把所有者设为 Administrators（可选，失败不影响主流程）
    subprocess.run(
        ["icacls", path, "/setowner", f"*{SID_ADMINISTRATORS}", "/T"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def setup_log_dir(cfg: dict, allow_non_admin: bool) -> str:
    """创建日志目录并加固其访问权限。返回日志目录路径。"""
    log_dir = cfg.get("log_dir") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "logs"
    )
    os.makedirs(log_dir, exist_ok=True)

    if os.name == "nt" and not allow_non_admin:
        _harden_acl_windows(log_dir)
    else:
        # 非 Windows / 联调：用文件权限尽量收窄（仅属主可读写）
        try:
            os.chmod(log_dir, 0o700)
        except Exception:
            pass
    return log_dir


class AppLogger:
    """极简文件日志。绝不记录口令与 Token。"""

    def __init__(self, log_dir: str, console: bool = True):
        self.log_dir = log_dir
        self.console = console
        self._lock = threading.Lock()
        self.path = os.path.join(log_dir, "yulan_cube.log")
        try:
            if os.name != "nt":
                # 日志文件本身也收窄权限
                open(self.path, "a").close()
                os.chmod(self.path, 0o600)
        except Exception:
            pass

    def _write(self, level: str, msg: str) -> None:
        line = f"[{_now_iso()}] [{level}] {msg}\n"
        with self._lock:
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line)
            except Exception:
                pass
        if self.console:
            sys.stdout.write(line)
            sys.stdout.flush()

    def info(self, msg: str) -> None:
        self._write("INFO", msg)

    def warn(self, msg: str) -> None:
        self._write("WARN", msg)

    def error(self, msg: str) -> None:
        self._write("ERROR", msg)


# ----------------------------------------------------------------------------
# 3) 配置加载
# ----------------------------------------------------------------------------
def default_config() -> dict:
    return {
        "listen_host": DEFAULT_HOST,
        "listen_port": DEFAULT_PORT,
        "token": "",                 # 必须与网站后台「欲蓝服务器口令」一致
        "log_dir": "",               # 留空则用程序同级 logs/ 目录
        "default_role": "user",      # 默认建号角色：user / admin
        "admin_products": [],        # 这些 product_id 建出的账号强制为管理员
        "admin_group_name": "administrators",   # 中文 Windows 可改为「管理员」
        "rdp_group_name": "Remote Desktop Users",  # 中文 Windows 可改为「远程桌面用户」
        "server_ip": "",             # 本机对外 IP（仅用于展示，网站后台另存）
        "use_powershell": False,     # True 时改用 PowerShell 建号/改密（口令不进入进程参数）
        "rename_method": "powershell",  # 改用户名方式：powershell（Rename-LocalUser）/ wmic（老系统）
    }


def load_config(path: str) -> dict:
    cfg = default_config()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                cfg.update(data)
        except Exception as e:
            sys.stderr.write(f"[配置] 读取 {path} 失败：{e}，使用默认值。\n")
    else:
        sys.stderr.write(f"[配置] 未找到 {path}，已生成默认配置样例。\n")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
    return cfg


def decide_role(cfg: dict, product_id: str) -> str:
    """由本 APP 决定账号角色：命中 admin_products 则为 admin，否则取 default_role。"""
    admins = cfg.get("admin_products") or []
    if product_id and product_id in admins:
        return "admin"
    role = str(cfg.get("default_role", "user")).lower()
    return "admin" if role == "admin" else "user"


# ----------------------------------------------------------------------------
# 4) Windows 账号创建 / 修改（net user / net localgroup / Rename-LocalUser）
# ----------------------------------------------------------------------------
def _validate_account(account: str) -> bool:
    import re
    return bool(re.match(ACCOUNT_RE_HINT, account or ""))


def _mask_password(args: list) -> list:
    """生成用于日志的「脱敏」参数副本：绝不打印明文口令。

    覆盖三种含口令的命令：
      - net user 账号 密码 /add      （建号，5 参数，索引 3 是密码）
      - net user 账号 新密码         （改密，4 参数，索引 3 是密码）
      - PowerShell ConvertTo-SecureString '密码'  （脚本内明文，正则脱敏）
    """
    import re
    a = list(args)
    # 改密命令只有 4 个参数，阈值必须是 >=4（旧版 >=5 会漏掉改密，导致明文进日志）
    if len(a) >= 4 and a[0] == "net" and a[1] == "user":
        a[3] = "***"
    # PowerShell 脚本中的明文口令同样脱敏
    for i, v in enumerate(a):
        if isinstance(v, str) and "ConvertTo-SecureString '" in v:
            a[i] = re.sub(r"ConvertTo-SecureString '[^']*'",
                          "ConvertTo-SecureString '***'", v)
    return a


def _run_cmd(args: list, use_powershell: bool, logger: AppLogger, dry_run: bool):
    """执行一条命令，返回 (returncode, combined_output)。dry_run 仅打印不执行。
    日志中打印的命令一律脱敏，绝不出现明文口令。"""
    safe = " ".join(_mask_password(args))
    if dry_run:
        logger.info(f"[DRY-RUN] 将执行：{safe}")
        return 0, "[dry-run] 未真正执行"
    logger.info(f"执行命令：{safe}")
    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, shell=False,
        )
        out = (proc.stdout or "").strip()
        if proc.returncode != 0:
            logger.warn(f"命令返回非零({proc.returncode})：{out}")
        return proc.returncode, out
    except Exception as e:
        logger.error(f"命令执行异常：{e}")
        return -1, str(e)


def _ps_script(account: str, password: str, role: str, admin_grp: str, rdp_grp: str) -> str:
    """PowerShell 版建号脚本：口令通过 SecureString 传入，不进入进程参数列表（更安全）。"""
    return (
        f"$pw = ConvertTo-SecureString '{password}' -AsPlainText -Force; "
        f"$u = New-LocalUser -Name '{account}' -Password $pw -ErrorAction Stop; "
        f"Add-LocalGroupMember -Group '{rdp_grp}' -Member '{account}' -ErrorAction SilentlyContinue; "
        + (f"Add-LocalGroupMember -Group '{admin_grp}' -Member '{account}' -ErrorAction SilentlyContinue; "
           if role == "admin" else "")
        + "exit 0"
    )


def _ps_set_password(account: str, password: str) -> str:
    """PowerShell 版改密脚本：管理员强制重置，不需要旧密码。"""
    return (
        f"$pw = ConvertTo-SecureString '{password}' -AsPlainText -Force; "
        f"Set-LocalUser -Name '{account}' -Password $pw -ErrorAction Stop; "
        "exit 0"
    )


def _ps_rename(old: str, new: str) -> str:
    """PowerShell 版改名脚本：只改登录名，SID 与组关系不变。"""
    return f"Rename-LocalUser -Name '{old}' -NewName '{new}' -ErrorAction Stop; exit 0"


def create_windows_account(account: str, password: str, role: str, cfg: dict,
                           logger: AppLogger, dry_run: bool) -> tuple[bool, str]:
    """
    在 Windows 上创建账号并返回 (是否成功, 明细)。
    命令契约（与需求一致）：
      - 普通：net user 用户名 密码 /add
      - 管理员：额外 net localgroup administrators 用户名 /add
      - 两者：net localgroup "Remote Desktop Users" 用户名 /add
    """
    if not _validate_account(account):
        return False, "账号名不合法（仅允许 1-20 位字母数字及 . _ -）"
    if not password or len(password) < 6:
        return False, "密码长度不足（至少 6 位）"

    admin_grp = cfg.get("admin_group_name") or "administrators"
    rdp_grp = cfg.get("rdp_group_name") or "Remote Desktop Users"
    use_ps = bool(cfg.get("use_powershell"))

    if use_ps:
        # PowerShell 路径：口令不暴露在进程参数，安全性更高（可选）
        script = _ps_script(account, password, role, admin_grp, rdp_grp)
        rc, out = _run_cmd(
            ["powershell", "-NoProfile", "-Command", script], False, logger, dry_run
        )
        ok = rc == 0
        return ok, (out if not ok else f"已通过 PowerShell 创建账号（角色={role}）")

    # 默认 net 命令路径（严格符合需求）
    # 1) 普通用户：net user 用户名 密码 /add
    rc1, out1 = _run_cmd(["net", "user", account, password, "/add"], False, logger, dry_run)
    if rc1 != 0:
        return False, f"net user 失败：{out1}"

    # 2) 管理员：额外 net localgroup administrators 用户名 /add
    if role == "admin":
        rc2, out2 = _run_cmd(
            ["net", "localgroup", admin_grp, account, "/add"], False, logger, dry_run
        )
        if rc2 != 0:
            return False, f"net localgroup {admin_grp} 失败：{out2}"

    # 3) 两者都要：net localgroup "Remote Desktop Users" 用户名 /add
    rc3, out3 = _run_cmd(
        ["net", "localgroup", rdp_grp, account, "/add"], False, logger, dry_run
    )
    if rc3 != 0:
        return False, f"net localgroup {rdp_grp} 失败：{out3}"

    return True, f"账号已创建（角色={role}）"


def update_windows_account(account: str, new_account: str, new_password: str, cfg: dict,
                           logger: AppLogger, dry_run: bool) -> tuple[bool, dict]:
    """
    以管理员权限强制修改已创建的账号（网站「控制台 / 商品详情」调用）。

    请求字段：
      account       当前账号名（旧名）
      new_account   新账号名（可选，空=不改）
      new_password  新密码（可选，空=不改）

    返回 (是否全部成功, {password_changed, renamed, final_account, detail})。
    顺序：先改密（用旧名），再改名 —— 改名后旧登录名即失效。
    """
    res = {
        "password_changed": False,
        "renamed": False,
        "final_account": account,
        "detail": "",
    }

    if not _validate_account(account):
        return False, {**res, "detail": "原账号名不合法"}
    if not new_account and not new_password:
        return False, {**res, "detail": "没有需要修改的内容（请提供新账号名或新密码）"}
    if new_account and new_account == account:
        return False, {**res, "detail": "新账号名与原账号名相同，无需修改"}
    if new_account and not _validate_account(new_account):
        return False, {**res, "detail": "新账号名不合法（仅允许 1-20 位字母数字及 . _ -）"}
    if new_password and len(new_password) < 6:
        return False, {**res, "detail": "新密码长度不足（至少 6 位）"}

    use_ps = bool(cfg.get("use_powershell"))
    details = []

    # 1) 改密码：net user 账号 新密码（不带 /add，管理员强制重置，不需旧密码）
    if new_password:
        if use_ps:
            cmd = ["powershell", "-NoProfile", "-Command",
                   _ps_set_password(account, new_password)]
        else:
            cmd = ["net", "user", account, new_password]
        rc, out = _run_cmd(cmd, False, logger, dry_run)
        if rc != 0:
            return False, {**res, "detail": f"改密码失败：{out}"}
        res["password_changed"] = True
        details.append("密码已重置")

    # 2) 改用户名：Rename-LocalUser（SID 不变，管理员组/远程桌面组关系保留）
    if new_account:
        method = str(cfg.get("rename_method") or "powershell").lower()
        if method == "wmic":
            # 兼容未安装 PowerShell LocalAccounts 模块的老系统
            cmd = ["wmic", "useraccount", "where", f"name='{account}'",
                   "call", "Rename", new_account]
        else:
            cmd = ["powershell", "-NoProfile", "-Command", _ps_rename(account, new_account)]
        rc, out = _run_cmd(cmd, False, logger, dry_run)
        if rc != 0:
            # 改密已成功、改名失败：如实返回部分结果，网站端据此提示用户
            tail = "（密码修改已生效）" if res["password_changed"] else ""
            return False, {**res, "detail": f"改用户名失败：{out}{tail}"}
        res["renamed"] = True
        res["final_account"] = new_account
        details.append(f"用户名已改为 {new_account}")

    return True, {**res, "detail": "；".join(details) or "无修改"}


# ----------------------------------------------------------------------------
# 5) HTTP 服务
# ----------------------------------------------------------------------------
def make_handler(cfg: dict, logger: AppLogger, dry_run: bool):
    token = str(cfg.get("token") or "")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        # 不向客户端暴露服务器版本
        server_version = "YulanCube/1.2"

        def log_message(self, fmt, *args):  # 覆盖默认 stderr 日志，统一走 AppLogger
            return

        def _send_json(self, code: int, payload: dict) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length", "0") or "0")
            except ValueError:
                length = 0
            if length <= 0:
                return {}
            raw = self.rfile.read(min(length, 1 << 20))  # 最多 1MB
            try:
                return json.loads(raw.decode("utf-8"))
            except Exception:
                return {}

        def _auth_ok(self) -> bool:
            if token == "":
                # 未配置 Token 视为拒绝（不允许空口令放行）
                return False
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return False
            provided = auth[len("Bearer "):].strip()
            # 恒定时间比较，避免时序侧信道
            return hmac.compare_digest(provided, token)

        def do_GET(self):
            if urlparse(self.path).path in ("/api/v1/health", "/api/v1/ping"):
                # 健康检查：仅返回非敏感的运行信息
                self._send_json(200, {
                    "ok": True,
                    "service": "yulan-cube",
                    "version": APP_VERSION,
                    "capabilities": ["create-user", "update-user"],
                    "default_role": decide_role(cfg, ""),
                    "admin_products": cfg.get("admin_products", []),
                    "server_ip": cfg.get("server_ip", ""),
                })
                return
            self._send_json(404, {"ok": False, "error": "not found"})

        def do_POST(self):
            path = urlparse(self.path).path
            if path not in ("/api/v1/create-user", "/api/v1/update-user"):
                self._send_json(404, {"ok": False, "error": "not found"})
                return

            if not self._auth_ok():
                logger.warn(f"鉴权失败（来源 {self.client_address[0]}）")
                self._send_json(401, {"ok": False, "error": "unauthorized"})
                return

            data = self._read_body()

            # ---------- 建号 ----------
            if path == "/api/v1/create-user":
                order_no = str(data.get("order_no", ""))
                product_id = str(data.get("product_id", ""))
                account = str(data.get("account", ""))
                password = str(data.get("password", ""))

                # 日志中只记账号，绝不记密码 / Token
                logger.info(
                    f"建号请求 order_no={order_no} product_id={product_id} account={account}"
                )

                role = decide_role(cfg, product_id)
                ok, detail = create_windows_account(
                    account, password, role, cfg, logger, dry_run
                )
                logger.info(f"建号结果 ok={ok} role={role} detail={detail}")

                self._send_json(200, {"ok": ok, "role": role, "detail": detail})
                return

            # ---------- 改号（管理员强制修改）----------
            account = str(data.get("account", ""))
            new_account = str(data.get("new_account", ""))
            new_password = str(data.get("new_password", ""))
            order_no = str(data.get("order_no", ""))

            # 日志中只记账号与「改了哪些项」，绝不记明文口令
            logger.info(
                f"改号请求 order_no={order_no} account={account} "
                f"改用户名={'是' if new_account else '否'} 改密码={'是' if new_password else '否'}"
            )

            ok, res = update_windows_account(
                account, new_account, new_password, cfg, logger, dry_run
            )
            logger.info(
                f"改号结果 ok={ok} 改密={res['password_changed']} "
                f"改名={res['renamed']} detail={res['detail']}"
            )
            self._send_json(200, {
                "ok": ok,
                "password_changed": res["password_changed"],
                "renamed": res["renamed"],
                "account": res["final_account"],
                "detail": res["detail"],
            })

    return Handler


# ----------------------------------------------------------------------------
# 6) 主入口
# ----------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="欲蓝财务魔方 Windows 服务端 APP")
    parser.add_argument("--config", default=CONFIG_FILENAME, help="配置文件路径")
    parser.add_argument("--host", default=None, help="监听地址（覆盖配置）")
    parser.add_argument("--port", type=int, default=None, help="监听端口（覆盖配置）")
    parser.add_argument("--dry-run", action="store_true", help="不真正执行建号命令（联调用）")
    parser.add_argument("--allow-non-admin", action="store_true",
                        help="允许非管理员运行（仅限本地联调，生产禁用）")
    parser.add_argument("--no-console", action="store_true", help="不向控制台输出日志")
    args = parser.parse_args()

    # 第 1 步：管理员检查（未通过直接退出，且不写任何日志文件）
    ensure_admin(args.allow_non_admin)

    cfg = load_config(args.config)

    # 命令行覆盖
    if args.host:
        cfg["listen_host"] = args.host
    if args.port:
        cfg["listen_port"] = args.port

    # 第 2 步：日志目录 + ACL 加固（其他用户不可见）
    log_dir = setup_log_dir(cfg, args.allow_non_admin)
    logger = AppLogger(log_dir, console=not args.no_console)

    logger.info("欲蓝财务魔方 APP 启动。"
                f"版本={APP_VERSION} 监听={cfg.get('listen_port')} 默认角色={cfg.get('default_role')} "
                f"管理员商品={cfg.get('admin_products')} "
                f"dry_run={args.dry_run}")
    if not cfg.get("token"):
        logger.warn("Token 未配置！任何建号/改号请求都将被拒绝，请先在配置中填写与网站一致的口令。")

    handler = make_handler(cfg, logger, args.dry_run)

    class Server(ThreadingHTTPServer):
        allow_reuse_address = True

    try:
        httpd = Server((cfg.get("listen_host", DEFAULT_HOST),
                        int(cfg.get("listen_port", DEFAULT_PORT))), handler)
    except OSError as e:
        logger.error(f"监听失败：{e}（端口可能被占用或权限不足）")
        return 1

    logger.info(f"已监听 http://{cfg.get('listen_host')}:{cfg.get('listen_port')}/api/v1/create-user")
    logger.info(f"          http://{cfg.get('listen_host')}:{cfg.get('listen_port')}/api/v1/update-user")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("收到停止信号，正在退出……")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
