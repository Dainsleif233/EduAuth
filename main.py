# EduAuth - 高校身份认证统一接口框架
# Copyright (C) 2025 Dainsleif
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""EduAuth 主程序入口。

职责边界:
    本文件负责配置加载、HTTP 服务、请求解析、后端调度与响应构建；
    auths/<id>/main.py 只负责实际的校验业务（含非法字符判定），
    返回 (status, message)，由本文件拼接成最终 output。

支持的请求格式:
    1. GET  /<id>?login=<username>&password=<password>
    2. POST /<id>  Content-Type: application/x-www-form-urlencoded
    3. POST /<id>  Content-Type: application/json

统一响应格式:
    {
        "results": [
            {
                "method": "<id>",
                "success": true/false,
                "output": "<output>",
                "error": ""
            }
        ]
    }
"""

import argparse
import atexit
import datetime
import importlib.util
import json
import logging
import os
import re
import signal
import sys
import traceback
from enum import IntEnum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, parse_qsl, unquote, urlparse

# TOML 读取: 3.11+ 用标准库 tomllib，3.8-3.10 若装了 tomli 则用它，
# 否则回退到本文件内的精简解析器（保证零依赖可用）。
try:
    import tomllib as _toml_reader  # type: ignore[import-not-found]
except ImportError:
    try:
        import tomli as _toml_reader  # type: ignore[import-not-found,no-redef]
    except ImportError:
        _toml_reader = None  # type: ignore[assignment]

# --------------------------------------------------------------------------- #
# 常量与默认值
# --------------------------------------------------------------------------- #

# AGPL-3.0 行为准则要求响应头如实声明协议，故 License 不可配置
LICENSE = "AGPL-3.0"

DEFAULT_SOURCE_REPO = "https://github.com/Dainsleif233/EduAuth"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 2268

CONFIG_NAME = "config.toml"

MAX_BODY_BYTES = 64 * 1024  # 请求体上限

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
AUTHS_DIR = os.path.join(ROOT_DIR, "auths")
DEFAULT_CONFIG_PATH = os.path.join(ROOT_DIR, CONFIG_NAME)
LOGS_DIR = os.path.join(ROOT_DIR, "logs")
DEFAULT_PID_FILE = os.path.join(ROOT_DIR, "eduauth.pid")

# output 由「状态前缀 + 分隔符 + 后端 message」拼接而成
OUTPUT_SEPARATOR = "\n"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("eduauth")


def setup_file_logging():
    # type: () -> Optional[str]
    """在 logs/ 下按启动时间新建日志文件，返回实际路径或 None。"""
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
        filename = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S.log")
        path = os.path.join(LOGS_DIR, filename)
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setFormatter(
            logging.Formatter(
                "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(handler)
        return path
    except OSError as exc:
        logger.warning("cannot create log file: %s", exc)
        return None


# --------------------------------------------------------------------------- #
# 守护进程相关
# --------------------------------------------------------------------------- #

import sys
import platform

def daemonize(pid_file=DEFAULT_PID_FILE):
    # type: (str) -> None
    """将当前进程转为守护进程（后台运行）。

    支持 Unix 和 Windows 平台。
    """
    # 检查是否已在运行
    if os.path.exists(pid_file):
        try:
            with open(pid_file, 'r') as f:
                old_pid = int(f.read().strip())
            # 检查进程是否存在
            os.kill(old_pid, 0)
            logger.error("EduAuth is already running (PID: %d)", old_pid)
            sys.exit(1)
        except (ValueError, ProcessLookupError, PermissionError, OSError):
            # PID 文件存在但进程不存在，可以继续
            pass

    if platform.system() == "Windows":
        # Windows: 使用 CREATE_NEW_PROCESS_GROUP 和 DETACHED_PROCESS 创建分离进程
        import subprocess
        # 设置环境变量，避免子进程重复调用 daemonize
        env = os.environ.copy()
        env['EDUAUTH_DAEMON'] = '1'
        # 重新启动当前脚本作为子进程，使用新窗口和分离标志
        cmd = [sys.executable] + sys.argv
        # 创建新的进程组和分离的进程
        creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
        # 打开日志文件重定向输出
        log_dir = os.path.join(ROOT_DIR, "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "daemon.log")
        with open(log_file, 'a') as log_fh:
            proc = subprocess.Popen(
                cmd,
                stdout=log_fh,
                stderr=log_fh,
                stdin=subprocess.DEVNULL,
                creationflags=creation_flags,
                cwd=ROOT_DIR,
                env=env
            )
        # 写入子进程的 PID
        try:
            with open(pid_file, 'w') as f:
                f.write(str(proc.pid))
            logger.info("PID file written: %s (PID: %d)", pid_file, proc.pid)
        except OSError as e:
            logger.warning("Cannot write PID file: %s", e)
        # 父进程退出
        sys.exit(0)
    else:
        # Unix: 使用双 fork 守护进程
        # 第一次 fork
        try:
            if os.fork() > 0:
                # 父进程退出
                sys.exit(0)
        except OSError as e:
            logger.error("First fork failed: %s", e)
            sys.exit(1)

        # 创建新会话
        os.setsid()

        # 第二次 fork
        try:
            if os.fork() > 0:
                # 第一个子进程退出
                sys.exit(0)
        except OSError as e:
            logger.error("Second fork failed: %s", e)
            sys.exit(1)

        # 重定向标准文件描述符到 /dev/null
        devnull = os.open(os.devnull, os.O_RDWR)
        os.dup2(devnull, 0)  # stdin
        os.dup2(devnull, 1)  # stdout
        os.dup2(devnull, 2)  # stderr
        os.close(devnull)

        # 写入 PID 文件
        try:
            with open(pid_file, 'w') as f:
                f.write(str(os.getpid()))
            logger.info("PID file written: %s (PID: %d)", pid_file, os.getpid())
        except OSError as e:
            logger.warning("Cannot write PID file: %s", e)

    # 注册退出清理
    def cleanup_pid_file():
        try:
            if os.path.exists(pid_file):
                os.remove(pid_file)
        except OSError:
            pass

    atexit.register(cleanup_pid_file)


def stop_daemon(pid_file=DEFAULT_PID_FILE):
    # type: (str) -> int
    """停止后台运行的 EduAuth 进程。"""
    if not os.path.exists(pid_file):
        logger.error("PID file not found: %s", pid_file)
        return 1

    try:
        with open(pid_file, 'r') as f:
            pid = int(f.read().strip())
    except (ValueError, IOError) as e:
        logger.error("Cannot read PID file: %s", e)
        return 1

    try:
        # 发送终止信号
        if platform.system() == "Windows":
            # Windows: 使用 taskkill 命令强制终止进程
            import subprocess
            result = subprocess.run(
                ['taskkill', '/F', '/PID', str(pid)],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                logger.info("Process %d stopped successfully", pid)
                try:
                    os.remove(pid_file)
                except OSError:
                    pass
                return 0
            else:
                logger.error("Failed to stop process %d: %s", pid, result.stderr)
                return 1
        else:
            # Unix: 使用 SIGTERM 信号
            os.kill(pid, signal.SIGTERM)
            logger.info("Sent SIGTERM to process %d", pid)

            # 等待进程退出
            import time
            for _ in range(10):  # 最多等待10秒
                try:
                    os.kill(pid, 0)  # 检查进程是否仍在运行
                    time.sleep(0.5)
                except ProcessLookupError:
                    logger.info("Process %d stopped successfully", pid)
                    # 清理 PID 文件
                    try:
                        os.remove(pid_file)
                    except OSError:
                        pass
                    return 0

            # 如果进程仍在运行，强制杀死
            logger.warning("Process %d did not stop gracefully, sending SIGKILL", pid)
            os.kill(pid, signal.SIGKILL)
            time.sleep(0.5)
            try:
                os.remove(pid_file)
            except OSError:
                pass
            return 0

    except ProcessLookupError:
        logger.error("Process %d not found", pid)
        try:
            os.remove(pid_file)
        except OSError:
            pass
        return 1
    except PermissionError:
        logger.error("Permission denied to stop process %d", pid)
        return 1
    except Exception as e:
        logger.error("Error stopping process %d: %s", pid, e)
        return 1


def get_daemon_status(pid_file=DEFAULT_PID_FILE):
    # type: (str) -> Tuple[bool, Optional[int]]
    """检查守护进程状态。返回 (is_running, pid)。"""
    if not os.path.exists(pid_file):
        return False, None

    try:
        with open(pid_file, 'r') as f:
            pid = int(f.read().strip())
    except (ValueError, IOError):
        return False, None

    try:
        if platform.system() == "Windows":
            # Windows: 使用 tasklist 检查进程是否存在
            import subprocess
            result = subprocess.run(
                ['tasklist', '/FI', 'PID eq {}'.format(pid)],
                capture_output=True,
                text=True
            )
            # 检查输出中是否包含 PID
            if 'Python' in result.stdout and str(pid) in result.stdout:
                return True, pid
            else:
                return False, pid
        else:
            # Unix: 使用 os.kill(pid, 0) 检查进程是否存在
            os.kill(pid, 0)
            return True, pid
    except ProcessLookupError:
        return False, pid
    except PermissionError:
        # 无权限检查，但进程可能存在
        return True, pid
    except Exception:
        # 其他异常，假设进程不存在
        return False, pid


# 让后端可以 import utils.* 下的通用工具
sys.path.insert(0, ROOT_DIR)


def _mask_sensitive(line):
    # type: (str) -> str
    """脱敏日志中可能出现的密码参数，防止凭据明文写入日志。"""
    return re.sub(r'(?i)(password|passwd|pwd)\s*=\s*\S+', r'\1=***', line)


class Status(IntEnum):
    """认证状态码，与源项目保持一致。"""

    SUCCESS = 0   # 认证成功
    FAILURE = 1   # 账号或密码错误
    ILLEGAL = 2   # 账号或密码含非法字符
    ERROR = 3     # 其他错误


# 各状态对应的 output 前缀
STATUS_PREFIX = {
    Status.SUCCESS: "EAP Success",
    Status.FAILURE: "EAP Failure",
    Status.ILLEGAL: "illegal",
    Status.ERROR: "error",
}

# 认证函数类型: (login, password) -> (status, message)
AuthFunc = Callable[[str, str], Tuple[int, str]]


class ConfigError(Exception):
    """配置文件格式非法。"""


# --------------------------------------------------------------------------- #
# TOML 读写
#
# 3.11+ 走标准库 tomllib；低版本无 tomli 时由下面的精简解析器兜底。
# 精简解析器只覆盖本项目配置用到的语法：注释、表头、字符串、整数、布尔。
# 遇到未支持的语法（数组、内联表、多行字符串等）会明确报错，不静默忽略。
# --------------------------------------------------------------------------- #

_BARE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")
_INT_LITERAL = re.compile(r"^[+-]?(?:0|[1-9](?:_?[0-9])*)$")
_ESCAPES = {
    '"': '"', "\\": "\\", "b": "\b", "f": "\f",
    "n": "\n", "r": "\r", "t": "\t",
}


def _strip_comment(line):
    # type: (str) -> str
    """去掉行尾注释；引号内的 # 不算注释。"""
    quote = ""
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            if char == "\\" and quote == '"':
                index += 1
            elif char == quote:
                quote = ""
        elif char in ('"', "'"):
            quote = char
        elif char == "#":
            return line[:index]
        index += 1
    return line


def _unquote(token, lineno):
    # type: (str, int) -> str
    """解析基本字符串与字面量字符串。"""
    if token.startswith('"""') or token.startswith("'''"):
        raise ConfigError("line {}: multi-line strings are not supported".format(lineno))

    if len(token) >= 2 and token.startswith("'") and token.endswith("'"):
        return token[1:-1]  # 字面量字符串不处理转义

    if len(token) < 2 or not (token.startswith('"') and token.endswith('"')):
        raise ConfigError("line {}: invalid string {!r}".format(lineno, token))

    out = []
    body = token[1:-1]
    index = 0
    while index < len(body):
        char = body[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        index += 1
        if index >= len(body):
            raise ConfigError("line {}: dangling escape".format(lineno))
        esc = body[index]
        if esc in _ESCAPES:
            out.append(_ESCAPES[esc])
            index += 1
        elif esc in ("u", "U"):
            width = 4 if esc == "u" else 8
            digits = body[index + 1:index + 1 + width]
            if len(digits) != width:
                raise ConfigError("line {}: truncated \\{} escape".format(lineno, esc))
            try:
                out.append(chr(int(digits, 16)))
            except ValueError:
                raise ConfigError("line {}: invalid \\{} escape".format(lineno, esc))
            index += 1 + width
        else:
            raise ConfigError("line {}: unknown escape \\{}".format(lineno, esc))
    return "".join(out)


def _parse_key(token, lineno):
    # type: (str, int) -> str
    if token.startswith(('"', "'")):
        return _unquote(token, lineno)
    if not _BARE_KEY.match(token):
        raise ConfigError("line {}: invalid key {!r}".format(lineno, token))
    return token


def _parse_value(token, lineno):
    # type: (str, int) -> Any
    if not token:
        raise ConfigError("line {}: missing value".format(lineno))
    if token in ("true", "false"):
        return token == "true"
    if token.startswith(('"', "'")):
        return _unquote(token, lineno)
    if _INT_LITERAL.match(token):
        return int(token.replace("_", ""))
    if token.startswith(("{",)):
        raise ConfigError(
            "line {}: inline tables are not supported".format(lineno)
        )
    if token.startswith("["):
        return _parse_array(token, lineno)
    raise ConfigError("line {}: unsupported value {!r}".format(lineno, token))


def _parse_array(token, lineno):
    # type: (str, int) -> List[Any]
    """解析 TOML 内联数组，仅支持字符串、整数、布尔。"""
    if not token.startswith("[") or not token.endswith("]"):
        raise ConfigError("line {}: unterminated array".format(lineno))
    inner = token[1:-1].strip()
    if not inner:
        return []
    items = []
    depth = 0
    current = ""
    in_quote = ""
    for ch in inner:
        if in_quote:
            current += ch
            if ch == "\\":
                continue
            if ch == in_quote:
                in_quote = ""
            continue
        if ch in ('"', "'"):
            in_quote = ch
            current += ch
        elif ch == "[":
            depth += 1
            current += ch
        elif ch == "]":
            depth -= 1
            current += ch
        elif ch == "," and depth == 0:
            items.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        items.append(current.strip())
    return [_parse_value(item, lineno) for item in items]


def toml_loads(text):
    # type: (str) -> Dict[str, Any]
    """解析 TOML 文本。优先用 tomllib / tomli，否则用精简解析器。"""
    if _toml_reader is not None:
        try:
            return _toml_reader.loads(text)
        except Exception as exc:  # TOMLDecodeError 类型随实现而异
            raise ConfigError(str(exc))
    return _toml_loads_minimal(text)


def _toml_loads_minimal(text):
    # type: (str) -> Dict[str, Any]
    """精简 TOML 解析器，仅覆盖本项目配置所需语法。"""
    root = {}  # type: Dict[str, Any]
    table = root
    defined = set()  # 已通过表头声明过的表路径

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw).strip()
        if not line:
            continue

        if line.startswith("["):
            if line.startswith("[["):
                raise ConfigError(
                    "line {}: arrays of tables are not supported".format(lineno)
                )
            if not line.endswith("]"):
                raise ConfigError("line {}: unterminated table header".format(lineno))
            table = root
            path_parts = []
            for part in line[1:-1].split("."):
                key = _parse_key(part.strip(), lineno)
                path_parts.append(key)
                table = table.setdefault(key, {})
                if not isinstance(table, dict):
                    raise ConfigError("line {}: {!r} is not a table".format(lineno, key))
            dotted = ".".join(path_parts)
            if dotted in defined:
                raise ConfigError(
                    "line {}: duplicate table definition {!r}".format(lineno, dotted)
                )
            defined.add(dotted)
            continue

        if "=" not in line:
            raise ConfigError("line {}: expected key = value".format(lineno))
        key_token, _, value_token = line.partition("=")
        key = _parse_key(key_token.strip(), lineno)
        if key in table:
            raise ConfigError("line {}: duplicate key {!r}".format(lineno, key))
        table[key] = _parse_value(value_token.strip(), lineno)

    return root


def _dump_key(key):
    # type: (str) -> str
    return key if _BARE_KEY.match(key) else json.dumps(key, ensure_ascii=False)


def _dump_value(value):
    # type: (Any) -> str
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        parts = [_dump_value(item) for item in value]
        return "[" + ", ".join(parts) + "]"
    return json.dumps(str(value), ensure_ascii=False)


def toml_dumps(data):
    # type: (Dict[str, Any]) -> str
    """把配置字典写成 TOML 文本（标量在前，表在后）。"""
    lines = []
    for key, value in data.items():
        if not isinstance(value, dict):
            lines.append("{} = {}".format(_dump_key(key), _dump_value(value)))
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append("")
            lines.append("[{}]".format(_dump_key(key)))
            for sub_key in sorted(value):
                lines.append(
                    "{} = {}".format(_dump_key(sub_key), _dump_value(value[sub_key]))
                )
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# 配置
# --------------------------------------------------------------------------- #


class Config:
    """运行时配置。

    config.toml:
        bind = ["127.0.0.1:2268"]
        source_repo = "https://github.com/Dainsleif233/EduAuth"

        [auths]
        ujs = false

    bind 是一组 "host:port" 字符串，支持多监听地址。
    兼容旧版 host / port 标量配置，启动时自动转换。

    [auths] 中值为 true 的后端才会被加载，未列出的视为关闭（默认全关）。
    """

    __slots__ = ("binds", "source_repo", "auths", "path")

    DEFAULT_BIND = "{}:{}".format(DEFAULT_HOST, DEFAULT_PORT)

    def __init__(self, binds=None, source_repo=DEFAULT_SOURCE_REPO,
                 auths=None, path=None):
        # type: (Optional[List[str]], str, Optional[Dict[str, bool]], Optional[str]) -> None
        self.binds = list(binds or [self.DEFAULT_BIND])
        self.source_repo = source_repo
        self.auths = dict(auths or {})
        self.path = path

    # ----- 查询 -----

    def is_enabled(self, auth_id):
        # type: (str) -> bool
        return bool(self.auths.get(auth_id.lower(), False))

    def is_known(self, auth_id):
        # type: (str) -> bool
        """该 id 是否出现在配置中（无论开关状态）。"""
        return auth_id.lower() in self.auths

    def enabled_ids(self):
        # type: () -> List[str]
        return sorted(k for k, v in self.auths.items() if v)

    # ----- 加载 -----

    @classmethod
    def load(cls, path):
        # type: (str) -> Config
        """从 TOML 文件加载配置。文件不存在时返回默认配置（全关）。"""
        if not os.path.isfile(path):
            logger.warning("config not found: %s (all backends disabled)", path)
            return cls(path=path)

        try:
            with open(path, "r", encoding="utf-8") as fp:
                text = fp.read()
        except OSError as exc:
            raise ConfigError("cannot read {}: {}".format(path, exc))

        try:
            data = toml_loads(text)
        except ConfigError as exc:
            raise ConfigError("{}: {}".format(path, exc))

        return cls.from_dict(data, path)

    @classmethod
    def from_dict(cls, data, path=None):
        # type: (Any, Optional[str]) -> Config
        """校验并构建配置对象。"""
        where = path or CONFIG_NAME
        if not isinstance(data, dict):
            raise ConfigError("{}: top level must be a table".format(where))

        # 兼容旧版 host / port 标量
        if "bind" in data:
            binds = data["bind"]
            if not isinstance(binds, list) or not binds:
                raise ConfigError(
                    "{}: bind must be a non-empty array of strings".format(where)
                )
            for item in binds:
                if not isinstance(item, str) or not item:
                    raise ConfigError(
                        "{}: each bind entry must be a non-empty string".format(where)
                    )
        else:
            host = data.get("host", DEFAULT_HOST)
            if not isinstance(host, str) or not host:
                raise ConfigError(
                    "{}: host must be a non-empty string".format(where)
                )
            port = data.get("port", DEFAULT_PORT)
            if isinstance(port, bool) or not isinstance(port, int) \
                    or not 1 <= port <= 65535:
                raise ConfigError(
                    "{}: port must be an integer in 1-65535".format(where)
                )
            binds = ["{}:{}".format(host, port)]

        source_repo = data.get("source_repo", DEFAULT_SOURCE_REPO)
        if not isinstance(source_repo, str) or not source_repo:
            raise ConfigError(
                "{}: source_repo must be a non-empty string".format(where)
            )

        raw_auths = data.get("auths", {})
        if not isinstance(raw_auths, dict):
            raise ConfigError(
                "{}: [auths] must be a table of id = bool".format(where)
            )

        auths = {}
        for key, value in raw_auths.items():
            if not isinstance(value, bool):
                raise ConfigError(
                    "{}: auths.{} must be true or false".format(where, key)
                )
            auths[str(key).lower()] = value

        return cls(binds, source_repo, auths, path)

    # ----- 生成 -----

    def to_dict(self):
        # type: () -> Dict[str, Any]
        return {
            "bind": self.binds,
            "source_repo": self.source_repo,
            "auths": {k: self.auths[k] for k in sorted(self.auths)},
        }

    def dumps(self):
        # type: () -> str
        return toml_dumps(self.to_dict())

    def save(self, path=None):
        # type: (Optional[str]) -> str
        """写出 TOML 配置文件，返回实际写入路径。"""
        target = path or self.path or DEFAULT_CONFIG_PATH
        with open(target, "w", encoding="utf-8") as fp:
            fp.write(self.dumps())
        self.path = target
        return target

    @classmethod
    def template(cls, auth_ids, path=None):
        # type: (List[str], Optional[str]) -> Config
        """按已存在的后端目录生成一份全关的配置。"""
        return cls(auths={i.lower(): False for i in auth_ids}, path=path)


def scan_auth_ids(auths_dir=AUTHS_DIR):
    # type: (str) -> List[str]
    """列出 auths/ 下所有可用后端 id（含 main.py 的子目录）。"""
    if not os.path.isdir(auths_dir):
        return []
    ids = []
    for entry in sorted(os.listdir(auths_dir)):
        if entry.startswith((".", "_")):
            continue
        if os.path.isfile(os.path.join(auths_dir, entry, "main.py")):
            ids.append(entry.lower())
    return ids


# 当前生效的配置；main() 中替换，供 Handler 读取
config = Config()


# --------------------------------------------------------------------------- #
# 后端注册与发现
# --------------------------------------------------------------------------- #


class BackendRegistry:
    """认证后端注册表，目录名即为后端 id。"""

    ENTRYPOINT = "authenticate"

    def __init__(self):
        # type: () -> None
        self._backends = {}  # type: Dict[str, AuthFunc]

    def register(self, auth_id, func):
        # type: (str, AuthFunc) -> None
        self._backends[auth_id.lower()] = func

    def get(self, auth_id):
        # type: (str) -> Optional[AuthFunc]
        return self._backends.get(auth_id.lower())

    def ids(self):
        # type: () -> List[str]
        return sorted(self._backends)

    def discover(self, enabled, auths_dir=AUTHS_DIR):
        # type: (List[str], str) -> None
        """只加载 enabled 中列出的后端，其余目录跳过不导入。"""
        for auth_id in enabled:
            entry_file = os.path.join(auths_dir, auth_id, "main.py")
            if not os.path.isfile(entry_file):
                logger.warning(
                    "backend %r is enabled but %s does not exist", auth_id, entry_file
                )
                continue
            try:
                self._load(auth_id, entry_file)
            except Exception:
                logger.warning(
                    "failed to load backend %r:\n%s", auth_id, traceback.format_exc()
                )

    def _load(self, auth_id, entry_file):
        # type: (str, str) -> None
        module_name = "auths.{}.main".format(auth_id)
        spec = importlib.util.spec_from_file_location(module_name, entry_file)
        if spec is None or spec.loader is None:
            raise ImportError("cannot create module spec for {}".format(entry_file))
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop(module_name, None)
            raise

        func = getattr(module, self.ENTRYPOINT, None)
        if not callable(func):
            raise AttributeError(
                "{} does not define callable {}()".format(entry_file, self.ENTRYPOINT)
            )
        self.register(auth_id, func)
        logger.info("registered backend: %s", auth_id)


registry = BackendRegistry()


# --------------------------------------------------------------------------- #
# 响应构建与调度
# --------------------------------------------------------------------------- #


def build_output(status, message):
    # type: (Status, str) -> str
    """拼接 output: 状态前缀 + 后端 message。"""
    prefix = STATUS_PREFIX[status]
    message = (message or "").strip()
    if not message:
        return prefix
    return prefix + OUTPUT_SEPARATOR + message


def build_result(method, status, message=""):
    # type: (str, Status, str) -> Dict[str, Any]
    """构建单条 result。error 按接口约定始终留空。"""
    return {
        "method": method,
        "success": status == Status.SUCCESS,
        "output": build_output(status, message),
        "error": "",
    }


def _normalize(raw):
    # type: (Any) -> Tuple[Status, str]
    """把后端返回值规范化成 (Status, message)。

    约定形式为 (status, message)；同时兼容只返回 status 的写法。
    """
    if isinstance(raw, tuple):
        if len(raw) != 2:
            raise TypeError("backend must return (status, message)")
        status_val, message = raw
        return Status(int(status_val)), "" if message is None else str(message)
    if isinstance(raw, bool):
        return (Status.SUCCESS if raw else Status.FAILURE), ""
    if isinstance(raw, int):
        return Status(int(raw)), ""
    raise TypeError("backend returned unsupported type: {!r}".format(type(raw).__name__))


def dispatch(auth_id, login, password):
    # type: (str, str, str) -> Dict[str, Any]
    """按 id 调度认证后端，返回单条 result。"""
    backend = registry.get(auth_id)
    if backend is None:
        if config.is_known(auth_id) and not config.is_enabled(auth_id):
            return build_result(
                auth_id, Status.ERROR, "handler disabled: {}".format(auth_id)
            )
        return build_result(
            auth_id, Status.ERROR, "handler not found: {}".format(auth_id)
        )

    # 仅检查参数是否存在，字符合法性由后端判定
    if not login or not password:
        return build_result(auth_id, Status.ERROR, "login and password are required")

    try:
        status, message = _normalize(backend(login, password))
    except NotImplementedError as exc:
        return build_result(auth_id, Status.ERROR, "not implemented: {}".format(exc))
    except ValueError as exc:
        return build_result(auth_id, Status.ERROR, "invalid status code: {}".format(exc))
    except Exception:
        logger.error("backend %s raised:\n%s", auth_id, traceback.format_exc())
        return build_result(auth_id, Status.ERROR, "internal error")

    return build_result(auth_id, status, message)


# --------------------------------------------------------------------------- #
# 请求体解析
# --------------------------------------------------------------------------- #


class ParseError(Exception):
    """请求体格式非法。"""


_DISPOSITION_NAME = re.compile(rb'name="([^"]*)"')


def _split_content_type(header):
    # type: (str) -> Tuple[str, Dict[str, str]]
    """拆分 Content-Type 为 mime 类型与参数字典。"""
    if not header:
        return "", {}
    parts = header.split(";")
    params = {}
    for item in parts[1:]:
        if "=" in item:
            key, value = item.split("=", 1)
            params[key.strip().lower()] = value.strip().strip('"')
    return parts[0].strip().lower(), params


def _parse_multipart(body, boundary, charset):
    # type: (bytes, str, str) -> Dict[str, str]
    """解析 multipart/form-data，只取普通文本字段。"""
    if not boundary:
        raise ParseError("multipart/form-data missing boundary")

    fields = {}
    delimiter = b"--" + boundary.encode("ascii", errors="replace")
    for chunk in body.split(delimiter):
        chunk = chunk.strip(b"\r\n")
        if not chunk or chunk == b"--":
            continue
        head, sep, content = chunk.partition(b"\r\n\r\n")
        if not sep:
            continue
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-disposition:"):
                match = _DISPOSITION_NAME.search(line)
                if match:
                    name = match.group(1).decode(charset, errors="replace")
                    fields[name] = content.rstrip(b"\r\n").decode(
                        charset, errors="replace"
                    )
                break
    return fields


def _parse_json(body, charset):
    # type: (bytes, str) -> Dict[str, str]
    """解析 JSON 请求体，标量字段转为字符串。"""
    try:
        data = json.loads(body.decode(charset))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ParseError("invalid JSON body: {}".format(exc))
    if not isinstance(data, dict):
        raise ParseError("JSON body must be an object")

    fields = {}
    for key, value in data.items():
        if value is None:
            fields[str(key)] = ""
        elif isinstance(value, (str, int, float, bool)):
            fields[str(key)] = value if isinstance(value, str) else str(value)
        else:
            raise ParseError(
                "JSON field {!r} must be a scalar, got {}".format(
                    key, type(value).__name__
                )
            )
    return fields


def parse_body(content_type, body):
    # type: (str, bytes) -> Dict[str, str]
    """按 Content-Type 解析请求体，未知类型按 urlencoded 兜底。"""
    mime, params = _split_content_type(content_type)
    charset = params.get("charset") or "utf-8"

    if mime == "application/json" or mime.endswith("+json"):
        return _parse_json(body, charset)
    if mime == "multipart/form-data":
        return _parse_multipart(body, params.get("boundary", ""), charset)
    return dict(
        parse_qsl(body.decode(charset, errors="replace"), keep_blank_values=True)
    )


# --------------------------------------------------------------------------- #
# HTTP 服务
# --------------------------------------------------------------------------- #


class EduAuthHandler(BaseHTTPRequestHandler):
    """HTTP 请求处理器。"""

    server_version = "EduAuth/1.0"
    protocol_version = "HTTP/1.1"
    timeout = 30  # 防止 slowloris 攻击占用线程

    # ----- 响应 -----

    def _set_headers(self, status=200, content_type="application/json; charset=utf-8"):
        # type: (int, str) -> None
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        # AGPL-3.0 行为准则要求的声明头
        self.send_header("X-Source-Repo", config.source_repo)
        self.send_header("X-License", LICENSE)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send_results(self, status_code, results):
        # type: (int, List[Dict[str, Any]]) -> None
        body = json.dumps({"results": results}, ensure_ascii=False).encode("utf-8")
        self._set_headers(status_code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error_result(self, status_code, method, message):
        # type: (int, str, str) -> None
        self._send_results(status_code, [build_result(method, Status.ERROR, message)])

    # ----- 请求解析 -----

    def _extract_id(self):
        # type: () -> Optional[str]
        """取 URL 路径最后一段作为后端 id（不区分大小写）。"""
        path = urlparse(self.path).path.strip("/")
        if not path:
            return None
        return unquote(path.split("/")[-1]).strip().lower()

    def _read_body(self):
        # type: () -> Optional[bytes]
        """读取请求体；超出上限时返回 None（响应已发出）。"""
        transfer = self.headers.get("Transfer-Encoding", "").lower()
        if "chunked" in transfer:
            return self._read_chunked()
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            self._send_error_result(
                413, self._extract_id() or "", "request body too large"
            )
            return None
        return self.rfile.read(length) if length > 0 else b""

    def _read_chunked(self):
        # type: () -> Optional[bytes]
        """解码 Transfer-Encoding: chunked 请求体。"""
        chunks = []
        total = 0
        while True:
            # 读取 chunk size（十六进制）
            size_line = self.rfile.readline(65537)
            if not size_line:
                self.close_connection = True
                self._send_error_result(
                    400, self._extract_id() or "", "incomplete chunked body"
                )
                return None
            size_str = size_line.strip()
            # chunk size 后面可能跟 ;extensions，取分号前的部分
            if b";" in size_str:
                size_str = size_str.split(b";", 1)[0]
            try:
                chunk_size = int(size_str, 16)
            except ValueError:
                self.close_connection = True
                self._send_error_result(
                    400, self._extract_id() or "", "invalid chunk size"
                )
                return None
            if chunk_size == 0:
                # 读取尾部 \r\n
                self.rfile.readline()
                break
            total += chunk_size
            if total > MAX_BODY_BYTES:
                self.close_connection = True
                self._send_error_result(
                    413, self._extract_id() or "", "request body too large"
                )
                return None
            data = self.rfile.read(chunk_size)
            if len(data) < chunk_size:
                self.close_connection = True
                self._send_error_result(
                    400, self._extract_id() or "", "incomplete chunked body"
                )
                return None
            chunks.append(data)
            # 读取 chunk 后的 \r\n
            self.rfile.readline()
        return b"".join(chunks)

    # ----- 各 HTTP 方法 -----

    def do_OPTIONS(self):
        # type: () -> None
        self._set_headers(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        # type: () -> None
        auth_id = self._extract_id()
        if not auth_id:
            self.close_connection = True
            self._send_error_result(400, "", "missing auth id in URL path")
            return

        params = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        login = params.get("login", [""])[0]
        password = params.get("password", [""])[0]

        self._send_results(200, [dispatch(auth_id, login, password)])

    def do_POST(self):
        # type: () -> None
        auth_id = self._extract_id()
        if not auth_id:
            self.close_connection = True
            self._send_error_result(400, "", "missing auth id in URL path")
            return

        body = self._read_body()
        if body is None:
            return

        try:
            fields = parse_body(self.headers.get("Content-Type", ""), body)
        except ParseError as exc:
            self.close_connection = True
            self._send_error_result(400, auth_id, str(exc))
            return

        login = fields.get("login", "")
        password = fields.get("password", "")

        self._send_results(200, [dispatch(auth_id, login, password)])

    def do_PUT(self):
        # type: () -> None
        self._method_not_allowed()

    def do_DELETE(self):
        # type: () -> None
        self._method_not_allowed()

    def do_PATCH(self):
        # type: () -> None
        self._method_not_allowed()

    def _method_not_allowed(self):
        # type: () -> None
        self.close_connection = True
        self._send_error_result(405, self._extract_id() or "", "method not allowed")

    # ----- 连接管理 -----

    def handle_one_request(self):
        # type: () -> None
        """覆盖基类，捕获 BrokenPipeError / TimeoutError 防止 traceback 逃逸。"""
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if not self.raw_requestline:
                self.close_connection = True
                return
            if not self.parse_request():
                return
            mname = 'do_' + self.command
            if not hasattr(self, mname):
                self.send_error(501, "Unsupported method (%r)" % self.command)
                return
            method = getattr(self, mname)
            method()
            self.log_request()
        except BrokenPipeError:
            self.close_connection = True
        except TimeoutError:
            self.close_connection = True
        except Exception:
            logger.error("request handling error:\n%s", traceback.format_exc())
            self.close_connection = True

    # ----- 日志 -----

    def log_message(self, format, *args):
        # type: (str, Any) -> None
        logger.info("%s %s", self.client_address[0], _mask_sensitive(format % args))


class EduAuthServer(ThreadingHTTPServer):
    """多线程 HTTP 服务器。

    认证后端通常要串行发起多个上游请求（阻塞且耗时），
    用线程模型避免单个慢请求阻塞整个服务。
    """

    daemon_threads = True
    allow_reuse_address = True


# --------------------------------------------------------------------------- #
# 启动
# --------------------------------------------------------------------------- #


def parse_args(argv):
    # type: (List[str]) -> argparse.Namespace
    """解析命令行参数。

    address 与 --config 均可省略；address 会覆盖配置文件中的 bind。
    address 格式: host:port 或 port，多个用逗号分隔。
    """
    parser = argparse.ArgumentParser(
        prog="eduauth", description="EduAuth - 高校身份认证统一接口框架"
    )
    parser.add_argument(
        "address",
        nargs="?",
        default=None,
        help="监听地址，形如 host:port、port 或逗号分隔的多个地址（覆盖配置文件）",
    )
    parser.add_argument(
        "-c",
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help="配置文件路径（默认 ./{}）".format(CONFIG_NAME),
    )
    parser.add_argument(
        "--init-config",
        action="store_true",
        help="按 auths/ 下的目录生成一份全关的配置文件后退出",
    )

    # 后台运行相关参数
    daemon_group = parser.add_argument_group("daemon", "后台运行模式")
    daemon_group.add_argument(
        "-d",
        "--daemon",
        action="store_true",
        help="以守护进程方式在后台运行",
    )
    daemon_group.add_argument(
        "--stop",
        action="store_true",
        help="停止后台运行的 EduAuth 进程",
    )
    daemon_group.add_argument(
        "--status",
        action="store_true",
        help="查看后台运行的 EduAuth 进程状态",
    )
    daemon_group.add_argument(
        "--pid-file",
        default=DEFAULT_PID_FILE,
        help="PID 文件路径（默认 ./eduauth.pid）",
    )
    daemon_group.add_argument(
        "--foreground",
        action="store_true",
        help="前台运行（默认行为，与 --daemon 互斥）",
    )

    args = parser.parse_args(argv)

    if args.address is not None:
        args.binds = _parse_bind_list(parser, args.address)
    else:
        args.binds = None
    return args


def _split_bind(parser, address):
    # type: (argparse.ArgumentParser, str) -> str
    """解析单个 host:port 或 port，返回标准 host:port 字符串。"""
    address = address.strip()
    if not address:
        parser.error("empty bind address")

    if ":" in address:
        host, _, port_str = address.rpartition(":")
        host = host or DEFAULT_HOST
    else:
        host, port_str = DEFAULT_HOST, address

    try:
        port = int(port_str)
    except ValueError:
        parser.error("invalid port: {!r}".format(port_str))

    if not 1 <= port <= 65535:
        parser.error("port out of range: {}".format(port))

    return "{}:{}".format(host, port)


def _parse_bind_list(parser, raw):
    # type: (argparse.ArgumentParser, str) -> List[str]
    """把逗号分隔的地址列表解析为 ["host:port", ...]。"""
    return [_split_bind(parser, part) for part in raw.split(",") if part.strip()]


def init_config(path):
    # type: (str) -> int
    """生成一份全关的配置模板。已存在则不覆盖。"""
    if os.path.exists(path):
        logger.error("config already exists: %s", path)
        return 1
    cfg = Config.template(scan_auth_ids(), path=path)
    cfg.save()
    logger.info(
        "config written: %s (backends: %s, all disabled)",
        path,
        ", ".join(cfg.auths) if cfg.auths else "none",
    )
    return 0


def main(argv=None):
    # type: (Optional[List[str]]) -> int
    global config

    args = parse_args(sys.argv[1:] if argv is None else argv)

    if args.init_config:
        return init_config(args.config)

    # 处理后台进程控制命令
    if args.stop:
        return stop_daemon(args.pid_file)

    if args.status:
        is_running, pid = get_daemon_status(args.pid_file)
        if is_running:
            print("EduAuth is running (PID: {})".format(pid))
            return 0
        else:
            print("EduAuth is not running")
            return 1

    log_path = setup_file_logging()
    if log_path:
        logger.info("logging to %s", log_path)

    try:
        config = Config.load(args.config)
    except ConfigError as exc:
        logger.error("%s", exc)
        return 1

    # 命令行地址覆盖配置文件
    if args.binds is not None:
        config.binds = args.binds

    for auth_id in scan_auth_ids():
        if not config.is_known(auth_id):
            logger.info("backend %r found but absent from config (disabled)", auth_id)

    enabled = config.enabled_ids()
    if not enabled:
        logger.warning("no backend enabled; every request will report not found")
    registry.discover(enabled)

    loaded = registry.ids()
    logger.info("loaded backends: %s", ", ".join(loaded) if loaded else "(none)")

    # 解析所有绑定地址
    bind_addrs = []
    for bind_str in config.binds:
        if ":" in bind_str:
            host, _, port_str = bind_str.rpartition(":")
            host = host or "0.0.0.0"
        else:
            host, port_str = "0.0.0.0", bind_str
        bind_addrs.append((host, int(port_str)))

    # 处理守护进程模式
    if args.daemon and not os.environ.get('EDUAUTH_DAEMON'):
        # 启动前 fork 到后台（如果还不是守护进程）
        daemonize(args.pid_file)

        # 注册信号处理
        def signal_handler(signum, frame):
            logger.info("Received signal %d, shutting down...", signum)
            sys.exit(0)

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

    servers = []
    for addr in bind_addrs:
        srv = EduAuthServer(addr, EduAuthHandler)
        servers.append(srv)
        logger.info("EduAuth listening on http://%s:%d", addr[0], addr[1])
    logger.info("source: %s (%s)", config.source_repo, LICENSE)

    if args.daemon:
        logger.info("running as daemon (PID: %d)", os.getpid())

    # 启动所有服务器（多线程，各自阻塞）
    try:
        threads = []
        for srv in servers:
            t = __import__("threading").Thread(
                target=srv.serve_forever, daemon=True
            )
            t.start()
            threads.append(t)
        # 主线程等待任意一个结束（通常不会发生）
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        logger.info("shutting down")
    finally:
        for srv in servers:
            srv.server_close()
        # 清理 PID 文件
        if args.daemon and os.path.exists(args.pid_file):
            try:
                os.remove(args.pid_file)
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
