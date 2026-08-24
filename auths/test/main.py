# Demo 后端（仅用于测试框架，不提供真实认证）
# Copyright (C) 2025 Dainsleif
# SPDX-License-Identifier: AGPL-3.0-or-later

"""演示用后端，用于验证框架调度、响应拼接、错误处理等行为。

不会发起任何真实请求，纯本地逻辑。
"""


# 测试账号
_TEST_ACCOUNTS = {
    "demo": "demo123",
    "admin": "admin",
    "test": "test",
}


def authenticate(login, password):
    # type: (str, str) -> tuple
    """演示认证。

    返回约定:
        0, "认证过程正常"   — demo/demo123
        1, "密码错误"        — 账号存在但密码不对
        2, "含非法字符"      — 账号或密码含非 ASCII 字符
        3, "服务不可用"      — 其他情况
    """
    # 非法字符检查（示例：只允许 ASCII 字母数字和 @._-）
    for ch in login + password:
        if ord(ch) > 127:
            return 2, "含非法字符"

    expected = _TEST_ACCOUNTS.get(login)
    if expected is None:
        return 3, "账号不存在"

    if password == expected:
        return 0, "认证过程正常"

    return 1, "密码错误"
