/**
 * General Network Logger for Frida
 * Targets: 
 * - Native libc (connect, send, recv, write, read)
 * - Java HttpURLConnection
 * - OkHttp (Common Android libraries)
 */

const Color = {
    RED: "\x1b[31m", GREEN: "\x1b[32m", YELLOW: "\x1b[33m",
    BLUE: "\x1b[34m", MAGENTA: "\x1b[35m", CYAN: "\x1b[36m", RESET: "\x1b[0m"
};

console.log(Color.BLUE + "[*] General Network Logger loaded." + Color.RESET);

// --- Native (libc) Hooks ---
function hookNative() {
    const libc = Process.findModuleByName("libc.so");
    if (!libc) return;

    // --- connect ---
    const connectPtr = libc.getExportByName("connect");
    if (connectPtr) {
        Interceptor.attach(connectPtr, {
            onEnter: function (args) {
                const fd = args[0].toInt32();
                const addrPtr = args[1];
                const family = addrPtr.readU16(); // sa_family_t

                if (family === 2) { // AF_INET
                    const port = (addrPtr.add(2).readU8() << 8) | addrPtr.add(3).readU8();
                    const ip = [
                        addrPtr.add(4).readU8(),
                        addrPtr.add(5).readU8(),
                        addrPtr.add(6).readU8(),
                        addrPtr.add(7).readU8()
                    ].join('.');
                    console.log(Color.CYAN + "[Native] connect(fd: " + fd + ", addr: " + ip + ":" + port + ")" + Color.RESET);
                } else if (family === 10) { // AF_INET6
                    // Simplified IPv6 logging
                    console.log(Color.CYAN + "[Native] connect(fd: " + fd + ", family: AF_INET6)" + Color.RESET);
                }
            }
        });
    }

    // --- send & write ---
    const sendTargets = ["send", "sendto", "write"];
    sendTargets.forEach(name => {
        const ptr = libc.getExportByName(name);
        if (!ptr) return;
        Interceptor.attach(ptr, {
            onEnter: function (args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.len = args[2].toInt32();
            },
            onLeave: function (retval) {
                const written = retval.toInt32();
                if (written > 0) {
                    try {
                        const data = this.buf.readUtf8String(Math.min(written, 1024));
                        if (data && (data.includes("HTTP") || data.includes("POST") || data.includes("GET") || data.includes("PUT"))) {
                            console.log(Color.YELLOW + "\n[Native Send] FD: " + this.fd + " | Length: " + written + Color.RESET);
                            console.log(data);
                        }
                    } catch (e) {
                        // Not UTF-8 or other error
                    }
                }
            }
        });
    });

    // --- recv & read ---
    const recvTargets = ["recv", "recvfrom", "read"];
    recvTargets.forEach(name => {
        const ptr = libc.getExportByName(name);
        if (!ptr) return;
        Interceptor.attach(ptr, {
            onEnter: function (args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
            },
            onLeave: function (retval) {
                const read = retval.toInt32();
                if (read > 0) {
                    try {
                        const data = this.buf.readUtf8String(Math.min(read, 1024));
                        if (data && data.includes("HTTP")) {
                            console.log(Color.GREEN + "\n[Native Recv] FD: " + this.fd + " | Length: " + read + Color.RESET);
                            console.log(data);
                        }
                    } catch (e) {
                        // Not UTF-8
                    }
                }
            }
        });
    });
}

// --- Java Hooks ---
function hookJava() {
    if (!Java.available) return;

    Java.perform(() => {
        // --- HttpURLConnection ---
        try {
            const HttpURLConnection = Java.use("java.net.HttpURLConnection");
            HttpURLConnection.getInputStream.implementation = function () {
                console.log(Color.MAGENTA + "\n[Java HttpURLConnection] Request URL: " + this.getURL().toString() + Color.RESET);
                console.log(Color.CYAN + "Method: " + this.getRequestMethod() + Color.RESET);
                
                // Get Request Headers
                const reqHeaders = this.getRequestProperties();
                if (reqHeaders) {
                    console.log("Request Headers: " + reqHeaders.toString());
                }

                const result = this.getInputStream();

                // Get Response Headers
                const resHeaders = this.getHeaderFields();
                if (resHeaders) {
                    console.log("Response Headers: " + resHeaders.toString());
                }

                return result;
            };
        } catch (e) {
            console.log("[!] java.net.HttpURLConnection not found or hook failed.");
        }

        // --- OkHttp 3.x ---
        try {
            const RealCall = Java.use("okhttp3.RealCall");
            RealCall.getResponseWithInterceptorChain.implementation = function () {
                const response = this.getResponseWithInterceptorChain();
                const request = response.request();
                
                console.log(Color.MAGENTA + "\n[Java OkHttp3] Request URL: " + request.url().toString() + Color.RESET);
                console.log(Color.CYAN + "Method: " + request.method() + Color.RESET);
                console.log("Request Headers: \n" + request.headers().toString());
                
                console.log(Color.GREEN + "Response Code: " + response.code() + Color.RESET);
                console.log("Response Headers: \n" + response.headers().toString());

                return response;
            };
        } catch (e) {
            // Might not be using OkHttp3
        }

        // --- Android System OkHttp (Legacy) ---
        try {
            const com_android_okhttp_RealCall = Java.use("com.android.okhttp.RealCall");
            com_android_okhttp_RealCall.getResponseWithInterceptorChain.implementation = function () {
                const response = this.getResponseWithInterceptorChain();
                const request = response.request();
                console.log(Color.MAGENTA + "\n[Java System OkHttp] Request URL: " + request.urlString() + Color.RESET);
                return response;
            };
        } catch (e) {}
    });
}

// Start hooking
hookNative();
hookJava();
