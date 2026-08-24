# UJS (江苏大学) 认证后端
# Copyright (C) 2025 Dainsleif
# SPDX-License-Identifier: AGPL-3.0-or-later

"""江苏大学统一身份认证后端。

复刻自 Go 版 Edu-Auth 的 UJS 实现，流程：
    1. GET  /cas/login              取 lt / pwdDefaultEncryptSalt / execution
    2. GET  /cas/needCaptcha.html   判断是否需要滑块验证码
    3. GET  /cas/sliderCaptcha.do   取滑块图，识别偏移量后验证取 sign
    4. POST /cas/login              提交 AES-CBC 加密后的密码

滑块验证码识别使用像素差分算法（与 Go 版完全一致），仅需 Pillow。
"""

import base64
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from typing import Optional

from utils.captcha import slide_comparison
from utils.crypto import aes_cbc_encrypt, random_str, timestamp_ms

BASE_URL = "https://pass.ujs.edu.cn/cas"
ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")

# 密码加密用的随机字符集（与 Go 版一致，去掉了易混字符）
_RANDOM_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"

_TIMEOUT = 15


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # 拒绝重定向，交由上层处理


def _build_client():
    # type: () -> urllib.request.OpenerDirector
    """构造带 cookie jar 且不自动跟随重定向的 opener。"""
    jar = CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), _NoRedirect()
    )


def _request(client, url, data=None):
    # type: (urllib.request.OpenerDirector, str, Optional[bytes]) -> tuple
    """发起请求，返回 (status, headers_dict, body_bytes)。

    302 等重定向会以 urllib.error.HTTPError 形式抛出，这里统一捕获后返回。
    """
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    req.add_header(
        "User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36",
    )
    if data is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        resp = client.open(req, timeout=_TIMEOUT)
        body = resp.read()
        return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as exc:
        body = exc.read() if exc.fp else b""
        return exc.code, dict(exc.headers), body


def _get_html(client):
    # type: (urllib.request.OpenerDirector) -> dict
    """取登录页的 lt / pwdDefaultEncryptSalt / execution。"""
    status, _headers, body = _request(client, BASE_URL + "/login")
    if status != 200:
        raise RuntimeError("get login page failed: {}".format(status))
    html = body.decode("utf-8", errors="replace")
    lt = re.search(r'name="lt" value="(.*?)"/>', html)
    salt = re.search(r'id="pwdDefaultEncryptSalt" value="(.*?)"/>', html)
    execution = re.search(r'name="execution" value="(.*?)"/>', html)
    if not lt or not salt:
        raise RuntimeError("html match error")
    return {
        "lt": lt.group(1),
        "salt": salt.group(1),
        "execution": execution.group(1) if execution else "",
    }


def _need_captcha(client, login):
    # type: (urllib.request.OpenerDirector, str) -> bool
    """判断是否需要滑块验证码。"""
    qs = urllib.parse.urlencode({
        "pwdEncrypt2": "pwdEncryptSalt",
        "_": timestamp_ms(),
        "username": login,
    })
    status, _headers, body = _request(client, BASE_URL + "/needCaptcha.html?" + qs)
    if status != 200:
        return True  # 出错时保守地认为需要
    return body.decode("utf-8", errors="replace").strip() == "true"


def _get_sign(client):
    # type: (urllib.request.OpenerDirector) -> str
    """滑块验证，最多重试 5 次取 sign。"""
    for _ in range(5):
        status, _headers, body = _request(
            client, BASE_URL + "/sliderCaptcha.do?_=" + str(timestamp_ms())
        )
        if status != 200:
            continue
        try:
            resp = json.loads(body.decode("utf-8", errors="replace"))
        except ValueError:
            continue

        big_image_num = resp.get("bigImageNum")
        big_image_b64 = resp.get("bigImage")
        if big_image_num is None or not big_image_b64:
            continue

        bg_path = os.path.join(ASSETS_DIR, "{}.png".format(big_image_num))
        try:
            with open(bg_path, "rb") as fp:
                bg_data = fp.read()
        except OSError:
            continue

        try:
            x, _y = slide_comparison(big_image_b64, bg_data)
        except Exception:
            continue

        qs = urllib.parse.urlencode({
            "canvasLength": 590,
            "moveLength": x,
        })
        status2, _headers2, body2 = _request(
            client, BASE_URL + "/verifySliderImageCode.do?" + qs
        )
        if status2 != 200:
            continue
        try:
            resp2 = json.loads(body2.decode("utf-8", errors="replace"))
        except ValueError:
            continue
        if resp2.get("code") == 0:
            return resp2.get("sign", "")
    raise RuntimeError("get sign failed after retries")


def _encrypt_pwd(pwd, salt):
    # type: (str, str) -> str
    """AES-CBC 加密密码后 base64，与 Go 版 encryptPwd 一致。"""
    prefix = random_str(_RANDOM_CHARS, 64)
    iv = random_str(_RANDOM_CHARS, 16)
    key = salt.strip().encode("utf-8")
    encrypted = aes_cbc_encrypt(
        (prefix + pwd).encode("utf-8"), key, iv.encode("utf-8")
    )
    return base64.b64encode(encrypted).decode("ascii")


def authenticate(login, password):
    # type: (str, str) -> tuple
    """执行 UJS 认证。

    Returns:
        (status, message)
            0 成功 / 1 账号或密码错误 / 2 含非法字符 / 3 其他错误
    """
    # 简单的非法字符检查（与 test 后端一致：只允许 ASCII）
    for ch in login + password:
        if ord(ch) > 127:
            return 2, "含非法字符"

    client = _build_client()

    try:
        page = _get_html(client)
    except Exception as exc:
        return 3, "获取登录页失败: {}".format(exc)

    try:
        password_encrypt = _encrypt_pwd(password, page["salt"])
    except Exception as exc:
        return 3, "密码加密失败: {}".format(exc)

    form = {
        "username": login,
        "password": password_encrypt,
        "dllt": "userNamePasswordLogin",
        "_eventId": "submit",
        "rmShown": "1",
        "sign": "",
        "lt": page["lt"],
        "execution": page["execution"],
    }

    try:
        if _need_captcha(client, login):
            form["sign"] = _get_sign(client)
    except Exception as exc:
        return 3, "滑块验证失败: {}".format(exc)

    try:
        data = urllib.parse.urlencode(form).encode("utf-8")
        status, headers, _body = _request(client, BASE_URL + "/login", data=data)
    except Exception as exc:
        return 3, "提交登录失败: {}".format(exc)

    if status == 302 and headers.get("Location") == "https://pass.ujs.edu.cn/cas/index.do":
        return 0, "认证过程正常"

    return 1, "用户名或密码错误"
