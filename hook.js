const Color = {
    RED: "\x1b[31m", GREEN: "\x1b[32m", YELLOW: "\x1b[33m",
    BLUE: "\x1b[34m", MAGENTA: "\x1b[35m", CYAN: "\x1b[36m", RESET: "\x1b[0m"
};

console.log(Color.BLUE + "[*] Script loaded. Waiting 1s before applying hooks..." + Color.RESET);

setTimeout(function () {
    const libc = Process.findModuleByName("libc.so");
    if (libc) {
        console.log(Color.GREEN + "[*] 1s delay finished. Applying libc hooks..." + Color.RESET);

        // 追踪哪些 FD 需要 Hook 响应 (cawd.php)
        const pendingFds = {};
        // 追踪哪些 FD 需要拦截并伪造响应 (xawd.php)
        const blockedFds = {};

        // --- Hook 发送函数 (send, sendto) ---
        const sendTargets = ["send", "sendto"];

        function isTargetHttp(buf, len) {
            if (len < 4) return false;
            try {
                const bytes = buf.readByteArray(Math.min(len, 4));
                const view = new Uint8Array(bytes);
                return (view[0] === 0x50 && view[1] === 0x4F && view[2] === 0x53 && view[3] === 0x54) || // POST
                    (view[0] === 0x47 && view[1] === 0x45 && view[2] === 0x54); // GET
            } catch (e) { return false; }
        }

        sendTargets.forEach(function (name) {
            const funcPtr = libc.getExportByName(name);
            if (!funcPtr) return;

            Interceptor.attach(funcPtr, {
                onEnter: function (args) {
                    const fd = args[0].toInt32();
                    const bufPtr = args[1];
                    const originalLen = args[2].toInt32();

                    if (bufPtr && originalLen > 0 && isTargetHttp(bufPtr, originalLen)) {
                        try {
                            let originalStr = bufPtr.readUtf8String(originalLen);

                            // 逻辑 A: 处理 cawd.php (记录 FD，后面修改它的真实响应)
                            if (originalStr.includes("/awcocxb2/cawd.php")) {
                                console.log(Color.YELLOW + "\n[!] Target Request Detected (cawd.php) on FD: " + fd + Color.RESET);
                                pendingFds[fd] = true;
                            }

                            // 逻辑 B: 处理 xawd.php (直接拦截，不让发出去)
                            if (originalStr.includes("/awcocxb2/xawd.php")) {
                                console.log(Color.MAGENTA + "\n[!] BLOCKING Request to xawd.php on FD: " + fd + Color.RESET);

                                this.isXawd = true;
                                this.origLen = originalLen;
                                this.fd = fd;

                                // 将发送长度改为 0，阻止数据发出
                                args[2] = ptr(0);

                                // 标记此 FD，在后续 recv 中返回伪造的成功内容
                                blockedFds[fd] = true;
                            }
                        } catch (e) { }
                    }
                },
                onLeave: function (retval) {
                    if (this.isXawd) {
                        // 告诉应用层：所有数据都“发送成功”了
                        retval.replace(ptr(this.origLen));
                        console.log(Color.GREEN + "[!] xawd.php intercepted: original length returned to app." + Color.RESET);
                    }
                }
            });
        });

        // --- Hook 接收函数 (recv, recvfrom, read) ---
        const recvTargets = ["recv", "recvfrom", "read"];

        recvTargets.forEach(function (name) {
            const funcPtr = libc.getExportByName(name);
            if (!funcPtr) return;

            Interceptor.attach(funcPtr, {
                onEnter: function (args) {
                    this.fd = args[0].toInt32();
                    this.buf = args[1];
                },
                onLeave: function (retval) {
                    const bytesRead = retval.toInt32();

                    // 处理 cawd.php 的真实响应修改
                    if (bytesRead > 0 && pendingFds[this.fd]) {
                        try {
                            console.log(Color.CYAN + "\n[!] Modifying Original Response (cawd.php, FD: " + this.fd + "):" + Color.RESET);
                            const originalData = this.buf.readByteArray(bytesRead);
                            console.log(hexdump(originalData, { offset: 0, length: bytesRead, header: true, ansi: true }));

                            const replacement = "9999999";
                            this.buf.writeUtf8String(replacement);
                            retval.replace(ptr(replacement.length));

                            console.log(Color.GREEN + "[!] Response modified to: " + replacement + Color.RESET);
                            delete pendingFds[this.fd];
                        } catch (e) {
                            console.error(Color.RED + "Error modifying cawd.php response: " + e + Color.RESET);
                        }
                    }

                    // 为 xawd.php 伪造一个“成功”的响应
                    if (blockedFds[this.fd]) {
                        try {
                            console.log(Color.MAGENTA + "\n[!] Faking Success Response for xawd.php (FD: " + this.fd + ")" + Color.RESET);

                            const fakeResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1\r\n\r\n1";
                            this.buf.writeUtf8String(fakeResponse);

                            retval.replace(ptr(fakeResponse.length));

                            console.log(Color.GREEN + "[!] Fake success '1' sent to app." + Color.RESET);
                            delete blockedFds[this.fd];
                        } catch (e) {
                            console.error(Color.RED + "Error faking xawd.php response: " + e + Color.RESET);
                        }
                    }
                }
            });
        });

        // 监听 FD 关闭
        const closePtr = libc.getExportByName("close");
        if (closePtr) {
            Interceptor.attach(closePtr, {
                onEnter: function (args) {
                    const fd = args[0].toInt32();
                    delete pendingFds[fd];
                    delete blockedFds[fd];
                }
            });
        }
    } else {
        console.error(Color.RED + "libc.so not found!" + Color.RESET);
    }
}, 1000);
