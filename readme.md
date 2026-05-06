# Android Lua Socket 请求拦截器 (Zygisk + Frida Gadget)

本项目提供了一种**免连接电脑、免外置 Frida-Server、永久常驻**的 Android 底层 Socket 请求拦截方案。

针对部分按键精灵/懒人精灵类脱机辅助（如 `com.awcocxb`），它们在底层子进程中直接使用 Lua 引擎调用 C 标准库 (`libc.so`) 的 `send`/`sendto` 发起原始 HTTP 请求，以此绕过常规的 Java 层抓包与 Hook (如 OkHttp/HttpURLConnection)。

本方案利用 **ZygiskFrida** 配合 **Frida Gadget Script 模式**，直接注入运行 Lua 引擎的守护子进程，实现对底层网络请求的精准拦截、篡改与阻断。

## ✨ 核心功能
*   **精准注入子进程**：绕过主进程 UI，直击执行 Lua 脚本的 `:sc` 后台引擎。
*   **延迟加载防崩溃**：完美解决 Hook 过早导致的 `url == null` 及 OkHttp 初始化空指针闪退问题。
*   **请求篡改 (cawd.php)**：拦截目标发包，伪造服务器返回的响应数据。
*   **请求阻断 (xawd.php)**：直接在 Native 层丢弃发包数据，并向应用层伪造 `HTTP 200 OK` 的成功响应。

## 📱 环境要求
1. **Root 权限**：设备必须已 Root（Magisk 或 KernelSU）。
2. **Zygisk 开启**：在 Magisk/KernelSU 设置中开启 Zygisk。
3. **ZygiskFrida 模块**：已在 Magisk 中刷入 `ZygiskFrida` 模块并重启设备。

***

## 🚀 部署指南 (Step-by-Step)

### 第一步：推送 JS 拦截脚本
将本项目的 `hook_awcocxb.js` 推送到手机的 `/data/local/tmp/` 目录下，并赋予执行权限。
```bash
adb push hook_awcocxb.js /data/local/tmp/
adb shell
su
chmod 777 /data/local/tmp/hook_awcocxb.js
```

### 第二步：配置 ZygiskFrida 目标进程
ZygiskFrida 的配置文件位于 `/data/local/tmp/re.zyg.fri/`。
我们需要**仅针对子进程 (`:sc`)** 进行注入，并设置 1000ms 延迟，以防止应用初始化网络环境时发生死锁崩溃。

在 `adb shell` 的 root 环境下执行：
```bash
cat << 'EOF' > /data/local/tmp/re.zyg.fri/config.json
{
    "targets": [
        {
            "app_name": "com.awcocxb:sc",
            "enabled": true,
            "start_up_delay_ms": 1000,
            "injected_libraries": [
                {
                    "path": "/data/local/tmp/re.zyg.fri/libgadget.so"
                }
            ]
        }
    ]
}
EOF
```

### 第三步：配置 Frida Gadget 自动运行脚本
让注入的 `libgadget.so` 在启动时自动读取我们的本地 JS 脚本（Script 模式），而不是等待电脑连接。

继续在 root 环境下执行：
```bash
cat << 'EOF' > /data/local/tmp/re.zyg.fri/libgadget.config.so
{
  "interaction": {
    "type": "script",
    "path": "/data/local/tmp/hook_awcocxb.js"
  }
}
EOF
```

### 第四步：处理权限问题 (重要)
部分高版本 Android 系统存在严格的 SELinux 限制，会导致普通应用的子进程无法读取 `/data/local/tmp/` 中的文件。
请确保文件权限正确，并**临时宽容 SELinux**（重启后失效，建议做成开机脚本）：
```bash
chmod -R 777 /data/local/tmp/re.zyg.fri/
setenforce 0
```

***

## 🔍 如何测试与查看日志

一切配置就绪后，直接在手机上启动目标 App，开启悬浮窗并运行脚本。
因为脱离了电脑终端，所有的拦截日志都会输出到 Android 系统的 Logcat 中。

你可以通过以下命令在电脑端或手机上的终端软件（如 Termux）中实时查看拦截效果：
```bash
adb logcat -s Frida
```
或者过滤特定关键词：
```bash
adb logcat | grep -E "Target Request|BLOCKING|Fake success|Modifying Original"
```

如果你在日志中看到如下输出，说明拦截与伪造已完美生效：
```text
[!] Target Request Detected (cawd.php) on FD: 60
[!] BLOCKING Request to xawd.php on FD: 62
[!] Fake success '1' sent to app.
```

***

## ❓ 常见问题排查 (FAQ)

**Q1: App 启动时卡死在闪屏页，或者直接闪退崩溃？**
*   **原因**：通常是因为注入了主进程 (`com.awcocxb`)，或者开启了 `child_gating` 的 `freeze` 模式，导致引擎初始化失败（抛出 `url == null` 异常）。
*   **解决**：检查 `config.json`，确保 `app_name` 严格写为 `com.awcocxb:sc`，不要写主包名，并且一定要保留 `"start_up_delay_ms": 1000`。

**Q2: 游戏正常运行了，但是没有任何 Frida 日志输出，也没有被拦截？**
*   **原因**：可能是 SELinux 拦截了脚本读取，或者是文件名/路径写错了。
*   **解决**：再次执行 `su -c "setenforce 0"`，并确保 `libgadget.config.so` 里面的路径与你推送 js 的路径完全一致。

**Q3: 如何适配其他按键精灵打包的 App？**
*   **解决**：按键精灵打包的脚本引擎通常运行在带有 `:sc`、`:shell` 或以奇怪随机字母结尾的子进程中。你可以通过运行脚本时输入 `adb shell "netstat -anp | grep 目标端口"` 找出实际发包的进程 PID，然后将 `config.json` 中的 `app_name` 改为对应的进程名即可。
