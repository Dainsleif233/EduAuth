# UJS 滑块验证码识别
# Copyright (C) 2025 Dainsleif
# SPDX-License-Identifier: AGPL-3.0-or-later

"""滑块验证码像素差分识别。

与 Go 版 ddddGocr ``SlideComparison`` 完全一致的算法：
逐像素计算 target（带缺口图）与 background（干净图）的 RGB 平均差值，
>80 标白，≤80 标黑；逐列扫描找到第一列有 ≥5 个白像素的位置，返回 x+2。

仅依赖 Pillow（可选 numpy 加速，无则纯 Python 降级）。
"""

import base64
import io
from typing import Tuple, Union

try:
    from PIL import Image  # type: ignore
except ImportError:
    Image = None  # type: ignore


def _decode_img(data):
    # type: (Union[bytes, str]) -> bytes
    """将 base64 字符串或 raw bytes 统一解码为 bytes。"""
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        if "," in data and data.startswith("data:"):
            data = data.split(",", 1)[1]
        return base64.b64decode(data)
    raise TypeError("unsupported image type: {}".format(type(data).__name__))


def slide_comparison(target_img, background_img):
    # type: (Union[bytes, str], Union[bytes, str]) -> Tuple[int, int]
    """对比两张同尺寸图，返回缺口左上角 ``(x, y)``。

    算法与 Go 版 ddddGocr ``SlideComparison`` 完全一致：
    逐像素 RGB 平均差 >80 → 白，否则黑；逐列扫描首列 ≥5 白像素 → x+2。

    Args:
        target_img: 带缺口的图片（服务器返回），bytes 或 base64 字符串
        background_img: 干净背景图（本地资产），bytes 或文件路径

    Returns:
        ``(x, y)`` 缺口在背景图中的像素坐标（y 始终为 0）
    """
    if Image is None:
        raise ImportError("Pillow is required; install with: pip install Pillow")

    target_bytes = _decode_img(target_img)

    if isinstance(background_img, str):
        try:
            bg_img = Image.open(background_img)
        except (OSError, TypeError):
            bg_bytes = _decode_img(background_img)
            bg_img = Image.open(io.BytesIO(bg_bytes))
    elif isinstance(background_img, bytes):
        bg_img = Image.open(io.BytesIO(background_img))
    else:
        bg_img = background_img  # type: ignore

    target = Image.open(io.BytesIO(target_bytes))

    if target.size != bg_img.size:
        raise ValueError(
            "image size mismatch: {} vs {}".format(target.size, bg_img.size)
        )

    target_rgb = target.convert("RGB")
    bg_rgb = bg_img.convert("RGB")
    width, height = target_rgb.size

    try:
        import numpy as np

        t_arr = np.asarray(target_rgb, dtype=np.int16)
        b_arr = np.asarray(bg_rgb, dtype=np.int16)
        avg_diff = np.abs(t_arr - b_arr).mean(axis=2)
        col_counts = (avg_diff > 80).sum(axis=0)
    except ImportError:
        t_data = list(target_rgb.getdata())
        b_data = list(bg_rgb.getdata())
        col_counts = [0] * width
        for i in range(len(t_data)):
            tr, tg, tb = t_data[i]
            br, bg_v, bb = b_data[i]
            if (abs(tr - br) + abs(tg - bg_v) + abs(tb - bb)) / 3.0 > 80:
                col_counts[i % width] += 1

    for x in range(width):
        if col_counts[x] >= 5:
            return x + 2, 0

    return 0, 0
