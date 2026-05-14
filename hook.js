/**
 * Optimized Native MITM Script (Short-circuiting)
 * Features: Native Logcat support for Zygisk-Frida / Background deployment
 */

const Color = {
    RED: "\x1b[31m", GREEN: "\x1b[32m", YELLOW: "\x1b[33m",
    BLUE: "\x1b[34m", MAGENTA: "\x1b[35m", CYAN: "\x1b[36m", RESET: "\x1b[0m"
};

// --- 0. 日志系统集成 (同时支持终端和 Logcat) ---
const logger = (function () {
    let nativeLog = null;
    try {
        const logPtr = Module.findExportByName("liblog.so", "__android_log_print");
        if (logPtr) {
            const logFunc = new NativeFunction(logPtr, 'int', ['int', 'pointer', 'pointer']);
            const tagPtr = Memory.allocUtf8String("FridaMITM");
            // 3 = DEBUG 级别
            nativeLog = (msg) => logFunc(3, tagPtr, Memory.allocUtf8String(msg));
        }
    } catch (e) { }

    return function (msg, color = "") {
        // 1. 输出到 Frida 终端 (带颜色)
        console.log(color + msg + Color.RESET);
        // 2. 输出到系统 Logcat (无颜色)
        if (nativeLog) {
            try { nativeLog(msg); } catch (e) { }
        }
    };
})();

logger("[*] Script loaded. Applying Native MITM hooks...", Color.BLUE);

// --- 1. 配置中心 ---
const MOCK_CONFIG = {
    "cawd.php": () => {
        const body = "爱玩豆(30.000个)≈0年30天0小时0分0秒";
        return buildFullResponse(body, true);
    },
    "xawd.php": () => buildFullResponse("1", false)
};

// --- 2. 核心辅助工具 ---
function getRealByteLen(str) {
    const m = Memory.allocUtf8String(str);
    let i = 0;
    while (m.add(i).readU8() !== 0) i++;
    return i;
}

function buildFullResponse(body, isChunked) {
    const date = new Date().toUTCString();
    let head = `HTTP/1.1 200 OK\r\nDate: ${date}\r\nServer: Apache/2.4.39 (Win64)\r\nContent-Type: text/html; charset=UTF-8\r\n`;

    if (isChunked) {
        const bodyLen = getRealByteLen(body);
        const hexLen = bodyLen.toString(16);
        return `${head}Transfer-Encoding: chunked\r\n\r\n${hexLen}\r\n${body}\r\n0\r\n\r\n`;
    } else {
        return `${head}Content-Length: ${getRealByteLen(body)}\r\n\r\n${body}`;
    }
}

// --- 3. 拦截引擎 ---
function init() {
    const libc = Process.findModuleByName("libc.so") || Process.getModuleByName("libc.so");
    if (!libc) return logger("libc.so not found!", Color.RED);

    const blockedFds = new Map();
    const POLLIN = 1;

    // A. 拦截发送
    ["send", "sendto", "write"].forEach(name => {
        const funcPtr = libc.findExportByName(name);
        if (!funcPtr) return;
        Interceptor.attach(funcPtr, {
            onEnter(args) {
                const fd = args[0].toInt32();
                const len = args[2].toInt32();
                if (len < 10) return;

                try {
                    const buf = args[1].readUtf8String(Math.min(len, 256));
                    for (const path in MOCK_CONFIG) {
                        if (buf.indexOf(path) !== -1) {
                            logger(`[!] Intercepted ${path} (FD: ${fd})`, Color.YELLOW);
                            this.fd = fd;
                            this.origLen = len;
                            args[2] = ptr(0);
                            blockedFds.set(fd, path);
                            break;
                        }
                    }
                } catch (e) { }
            },
            onLeave(retval) {
                if (this.fd) retval.replace(ptr(this.origLen));
            }
        });
    });

    // B. 伪造事件循环 (Poll)
    const pollPtr = libc.findExportByName("poll");
    if (pollPtr) {
        Interceptor.attach(pollPtr, {
            onEnter(args) { this.fds = args[0]; this.nfds = args[1].toInt32(); },
            onLeave(retval) {
                for (let i = 0; i < this.nfds; i++) {
                    const fdPtr = this.fds.add(i * 8);
                    const fd = fdPtr.readInt();
                    if (blockedFds.has(fd)) {
                        fdPtr.add(6).writeShort(POLLIN);
                        if (retval.toInt32() === 0) retval.replace(ptr(1));
                        logger(`[*] Spoofed Poll for FD ${fd}`, Color.CYAN);
                    }
                }
            }
        });
    }

    // C. 注入响应
    ["recv", "recvfrom", "read"].forEach(name => {
        const funcPtr = libc.findExportByName(name);
        if (!funcPtr) return;
        Interceptor.attach(funcPtr, {
            onEnter(args) { this.fd = args[0].toInt32(); this.buf = args[1]; },
            onLeave(retval) {
                const path = blockedFds.get(this.fd);
                if (path) {
                    const fakeRes = MOCK_CONFIG[path]();
                    const realLen = getRealByteLen(fakeRes);
                    this.buf.writeUtf8String(fakeRes);
                    retval.replace(ptr(realLen));
                    logger(`[!] Injected Fake ${path} (${realLen} bytes)`, Color.GREEN);
                    blockedFds.delete(this.fd);
                }
            }
        });
    });

    // D. 资源清理
    const closePtr = libc.findExportByName("close");
    if (closePtr) {
        Interceptor.attach(closePtr, { onEnter(args) { blockedFds.delete(args[0].toInt32()); } });
    }
}

try {
    init();
} catch (e) {
    logger(`Initialization failed: ${e}`, Color.RED);
}
