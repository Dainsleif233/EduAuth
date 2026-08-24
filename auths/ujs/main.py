# UJS (江苏大学) 认证后端
# Copyright (C) 2025 Dainsleif
# SPDX-License-Identifier: AGPL-3.0-or-later

"""江苏大学统一身份认证后端。

本文件只负责实际的校验业务（含非法字符判定）；
HTTP 服务、请求解析、output 拼接由主程序完成。

TODO: 实现认证流程（参考 Go 版 pass.ujs.edu.cn/cas 流程）:
    1. GET  /cas/login              取 lt / pwdDefaultEncryptSalt / execution
    2. GET  /cas/needCaptcha.html   判断是否需要滑块验证码
    3. GET  /cas/sliderCaptcha.do   取滑块图，识别偏移量后验证取 sign
    4. POST /cas/login              提交 AES-CBC 加密后的密码
"""

import os

# 资源文件目录（滑块底图等）
ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")

BASE_URL = "https://pass.ujs.edu.cn/cas"


def authenticate(login, password):
    # type: (str, str) -> tuple
    """执行 UJS 认证。

    Args:
        login: 用户名
        password: 密码

    Returns:
        (status, message)
            status: 0 成功 / 1 账号或密码错误 / 2 含非法字符 / 3 其他错误
            message: 详细信息，由主程序拼接到状态前缀之后
    """
    raise NotImplementedError("ujs backend is not implemented yet")
