# ujs 后端

江苏大学（UJS）统一身份认证后端。

## 依赖

```bash
pip install Pillow
```

## 开启

在 `config.toml` 中：

```toml
[auths]
ujs = true
```

## 认证流程

```
1. GET  /cas/login              → 提取 lt / pwdDefaultEncryptSalt / execution
2. GET  /cas/needCaptcha.html   → 判断是否需要滑块验证码
3. GET  /cas/sliderCaptcha.do   → 获取滑块图片，识别缺口位置后验证取 sign
4. POST /cas/login              → 提交 AES-CBC 加密后的密码
```

- 成功：302 重定向到 `/cas/index.do`
- 失败：其他响应 → 账号或密码错误

## 滑块验证码识别

使用**像素差分算法**（与 Go 版 `ddddGocr.SlideComparison` 完全一致）：

1. 逐像素计算带缺口图与干净图的 RGB 平均差值
2. 差值 >80 标白，≤80 标黑
3. 逐列扫描，找到第一列有 ≥5 个白像素的位置
4. 返回 x+2 作为滑块偏移量

## 资源文件

`assets/` 下的 `0.png` ~ `9.png` 是 UJS 服务端预定义的滑块背景图（590×360），由 `sliderCaptcha.do` 返回的 `bigImageNum` 字段索引。
