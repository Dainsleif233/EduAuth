# EduAuth

本衍生作品基于 [Dainsleif233/Edu-Auth](https://github.com/Dainsleif233/Edu-Auth) 构建，遵循 AGPL-3.0 协议。

## 简介

EduAuth 是一个用 Python 实现的高校身份认证统一接口框架，将各高校的身份认证转换成 Eduroam 特征的响应格式。

主程序负责 HTTP 服务、请求解析、后端调度与响应构建；`auths/<id>/main.py` 只负责实际的校验业务，返回 `(status, message)`。

## 运行要求

- Python 3.8+
- 框架本身无外部依赖（仅标准库）；各后端可按需自行引入依赖

## 配置

首次运行前生成配置文件：

```bash
python main.py --init-config     # 按 auths/ 下的目录生成 config.toml，默认全部关闭
```

`config.toml`：

```toml
host = "127.0.0.1"
port = 2268

# 响应头 X-Source-Repo 的值；Fork 后须改成自己的仓库地址
source_repo = "https://github.com/Dainsleif233/EduAuth"

[auths]
test = false
ujs = false
```

| 字段 | 说明 | 默认 |
|------|------|------|
| `host` | 监听地址 | `127.0.0.1` |
| `port` | 监听端口 | `2268` |
| `source_repo` | 响应头 `X-Source-Repo` 的值，Fork 后须改成自己的仓库地址 | 本仓库地址 |
| `[auths]` | 各后端开关，`true` 才加载 | 全部 `false` |

**默认全部关闭**：`[auths]` 中值为 `false` 或未列出的后端不会被导入，请求它会返回 `handler disabled` / `handler not found`。配置文件不存在时同样视为全关。

`X-License` 固定为 `AGPL-3.0`，不可配置。

TOML 解析在 Python 3.11+ 走标准库 `tomllib`；3.8–3.10 若已安装 `tomli` 则用它，否则回退到内置的精简解析器，因此无需任何依赖也能运行。

## 启动

```bash
python main.py                    # 读取 ./config.toml
python main.py -c /path/cfg.toml  # 指定配置文件
python main.py 8080               # 覆盖配置中的端口
python main.py 0.0.0.0:8080       # 覆盖配置中的地址和端口
```

## 请求格式

支持三种方式调用认证接口：

### 1. GET 请求

```
GET /<id>?login=<username>&password=<password>
```

### 2. POST 表单

```
POST /<id>
Content-Type: application/x-www-form-urlencoded

login=<username>&password=<password>
```

也支持 `multipart/form-data`。

### 3. POST JSON

```
POST /<id>
Content-Type: application/json

{"login": "<username>", "password": "<password>"}
```

## 响应格式

```json
{
    "results": [
        {
            "method": "<id>",
            "success": true,
            "output": "EAP Success\n认证过程正常",
            "error": ""
        }
    ]
}
```

- `output` = 状态前缀 + 换行 + 后端 message。账号或密码错误时前缀为 `EAP Failure`，含非法字符时为 `illegal`
- `error` 始终留空
- `<id>` 不区分大小写；路径为多段时取最后一段

所有响应均包含以下头部（`X-Source-Repo` 取自配置）：

```
X-Source-Repo: https://github.com/Dainsleif233/EduAuth
X-License: AGPL-3.0
```

## 项目结构

```
├── auths/              # 认证后端
│   ├── ujs/
│   │   ├── assets/     # 资源文件
│   │   └── main.py     # 后端主程序入口
│   ├── test/
│   │   ├── README.md   # 测试账号说明
│   │   └── main.py     # 演示后端
│   └── <id>/
│       └── main.py
├── utils/              # 通用工具（验证码识别、加解密等）
├── main.py             # 主程序入口
├── config.example.toml # 配置模板
├── LICENSE
├── CODE_OF_CONDUCT.md
└── README.md
```

## 开发后端

在 `auths/` 下新建目录，目录名即为认证 ID（小写，蛇形命名），在其中创建 `main.py` 并实现 `authenticate` 函数：

```python
def authenticate(login, password):
    """返回 (status, message)。"""
    if not _charset_ok(login):
        return 2, "用户名含非法字符"
    if _login(login, password):
        return 0, "认证过程正常"
    return 1, "用户名或密码错误"
```

状态码约定：

| status | 含义 | output 前缀 |
|--------|------|-------------|
| 0 | 认证成功 | `EAP Success` |
| 1 | 账号或密码错误 | `EAP Failure` |
| 2 | 账号或密码含非法字符 | `illegal` |
| 3 | 其他错误 | `error` |

非法字符的判定规则由各后端自行决定（各校账号命名规则不同）。message 可为空，此时 output 只有前缀；只返回 status 也可以。

新增后端后，需在 `config.toml` 的 `[auths]` 中把它设为 `true` 才会被加载（默认全关）。资源文件放在该后端目录的 `assets/` 下，用相对本文件的路径引用：

```python
import os
ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
```

跨学校复用的逻辑（验证码识别、加解密等）放进 `utils/`，后端里直接 `from utils.xxx import yyy`。

## 参与开发

### 1. 熟悉 Python

自行按上述约定提交 api 接口，或协助优化代码和解决 issue。

### 2. 不会 Python

- 若已有方案，发 issue 提交 api 接口方案
- 若无方案，发 issue 留下需求

## 衍生作品

若想要 Fork 本仓库，请务必保留 AGPL-3.0 协议，并遵守 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)：

1. **“网络交互即触发开源”**：任何通过网络提供服务的衍生作品（如 SaaS API），无论是否分发代码，必须公开修改后的全部源码。

2. 用户访问 API 即有权获取对应源码（需在 API 文档或响应头中声明源码获取方式）。

## 许可证

[AGPL-3.0](LICENSE)
