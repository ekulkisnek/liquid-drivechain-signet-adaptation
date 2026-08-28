#!/usr/bin/env bash
# Exact-SHA Windows x86_64 MinGW release recipe for Ubuntu hosts and runners.
set -euo pipefail

REPO=${REPO:-$(git rev-parse --show-toplevel)}
ARTIFACT_DIR=${ARTIFACT_DIR:-"$REPO/release-artifacts"}
LOG_DIR=${LOG_DIR:-"$REPO/release-logs"}
SHA=bf8e9e1e5a6453b3a0573ff57cf9c92b2b3afe2b
SHORT=bf8e9e1e
JOBS=${JOBS:-1}
LOG="$LOG_DIR/windows-build.log"

mkdir -p "$ARTIFACT_DIR" "$LOG_DIR"
exec > >(tee "$LOG") 2>&1

echo "== Windows x86_64 Elements Drivechain release build =="
date -u '+date_utc=%Y-%m-%dT%H:%M:%SZ'
echo "repo=https://github.com/ekulkisnek/liquid-drivechain-signet-adaptation"
echo "target_sha=$SHA"
echo "jobs=$JOBS"
echo "uname=$(uname -a)"
. /etc/os-release
echo "os=$PRETTY_NAME"
echo "build_arch=$(uname -m)"
echo "gcc=$({ gcc --version | head -n1; } 2>/dev/null)"
echo "mingw_gcc=$({ x86_64-w64-mingw32-gcc --version | head -n1; } 2>/dev/null)"
echo "mingw_g++=$({ x86_64-w64-mingw32-g++ --version | head -n1; } 2>/dev/null)"
echo "mingw_ld=$({ x86_64-w64-mingw32-ld --version | head -n1; } 2>/dev/null)"

STATUS_FILE=/proc/sys/fs/binfmt_misc/status
RESTORE_BINFMT=
if [ -w "$STATUS_FILE" ]; then
  RESTORE_BINFMT=$(cat "$STATUS_FILE" 2>/dev/null || true)
  echo 0 > "$STATUS_FILE" 2>/dev/null || true
  echo "binfmt_misc_temporarily_disabled=1"
fi
cleanup() {
  if [ -n "$RESTORE_BINFMT" ] && [ -w "$STATUS_FILE" ]; then
    echo "$RESTORE_BINFMT" > "$STATUS_FILE" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

cd "$REPO"
echo "source_sha=$(git rev-parse HEAD)"
test "$(git rev-parse HEAD)" = "$SHA"
echo "git_status_begin=$(git status --short | wc -l)"
git diff --quiet

echo "build_command=make -C depends HOST=x86_64-w64-mingw32 NO_QT=1 NO_UPNP=1 NO_NATPMP=1 NO_ZMQ=1 NO_QR=1 NO_BDB=1 -j$JOBS"
make -C depends HOST=x86_64-w64-mingw32 \
  NO_QT=1 \
  NO_UPNP=1 \
  NO_NATPMP=1 \
  NO_ZMQ=1 \
  NO_QR=1 \
  NO_BDB=1 \
  -j"$JOBS"

echo "build_command=./autogen.sh"
./autogen.sh

CONFIGURE_CMD=(
  ./configure
  --prefix=/
  --without-gui
  --disable-tests
  --disable-bench
  --disable-man
  --disable-ccache
  --with-daemon=yes
  --with-utils=yes
  --with-libs=no
  --enable-wallet
  --with-sqlite=yes
  --without-bdb
)
echo "build_command=CONFIG_SITE=$REPO/depends/x86_64-w64-mingw32/share/config.site ${CONFIGURE_CMD[*]}"
CONFIG_SITE="$REPO/depends/x86_64-w64-mingw32/share/config.site" "${CONFIGURE_CMD[@]}"

echo "build_command=make -C src -j$JOBS elementsd.exe elements-cli.exe"
make -C src -j"$JOBS" elementsd.exe elements-cli.exe

echo "elementsd_exe_file=$(file -b src/elementsd.exe)"
echo "elements_cli_exe_file=$(file -b src/elements-cli.exe)"

OUT="$ARTIFACT_DIR/liquid-signet-elements-$SHORT-windows-x86_64"
ZIPFILE="$ARTIFACT_DIR/liquid-signet-elements-$SHORT-windows-x86_64.zip"
rm -rf "$OUT" "$ZIPFILE"
mkdir -p "$OUT"

cp src/elementsd.exe "$OUT/elementsd.exe"
cp src/elements-cli.exe "$OUT/elements-cli.exe"
x86_64-w64-mingw32-strip "$OUT/elementsd.exe" "$OUT/elements-cli.exe"

cat > "$OUT/liquid-signet.c" <<'WRAPPER'
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shellapi.h>
#include <wchar.h>
#include <stdlib.h>

typedef struct {
    wchar_t* data;
    size_t len;
    size_t cap;
} StrBuf;

static void die_alloc(void) { ExitProcess(111); }

static void sb_init(StrBuf* b) {
    b->cap = 4096;
    b->len = 0;
    b->data = (wchar_t*)calloc(b->cap, sizeof(wchar_t));
    if (!b->data) die_alloc();
}

static void sb_need(StrBuf* b, size_t extra) {
    if (b->len + extra + 1 <= b->cap) return;
    while (b->len + extra + 1 > b->cap) b->cap *= 2;
    wchar_t* p = (wchar_t*)realloc(b->data, b->cap * sizeof(wchar_t));
    if (!p) die_alloc();
    b->data = p;
}

static void sb_add(StrBuf* b, const wchar_t* s) {
    size_t n = wcslen(s);
    sb_need(b, n);
    memcpy(b->data + b->len, s, n * sizeof(wchar_t));
    b->len += n;
    b->data[b->len] = 0;
}

static void sb_add_ch(StrBuf* b, wchar_t c) {
    sb_need(b, 1);
    b->data[b->len++] = c;
    b->data[b->len] = 0;
}

static void quote_arg(StrBuf* b, const wchar_t* arg) {
    int need_quote = (*arg == 0);
    for (const wchar_t* p = arg; *p; ++p) {
        if (*p == L' ' || *p == L'\t' || *p == L'"') {
            need_quote = 1;
            break;
        }
    }
    if (!need_quote) {
        sb_add(b, arg);
        return;
    }
    sb_add_ch(b, L'"');
    int backslashes = 0;
    for (const wchar_t* p = arg; ; ++p) {
        if (*p == L'\\') {
            backslashes++;
        } else if (*p == L'"') {
            for (int i = 0; i < backslashes * 2 + 1; ++i) sb_add_ch(b, L'\\');
            sb_add_ch(b, *p);
            backslashes = 0;
        } else {
            if (*p == 0) {
                for (int i = 0; i < backslashes * 2; ++i) sb_add_ch(b, L'\\');
                break;
            }
            for (int i = 0; i < backslashes; ++i) sb_add_ch(b, L'\\');
            backslashes = 0;
            sb_add_ch(b, *p);
        }
    }
    sb_add_ch(b, L'"');
}

static wchar_t* xwcsdup(const wchar_t* s) {
    size_t n = wcslen(s) + 1;
    wchar_t* out = (wchar_t*)malloc(n * sizeof(wchar_t));
    if (!out) die_alloc();
    memcpy(out, s, n * sizeof(wchar_t));
    return out;
}

static int starts_with(const wchar_t* s, const wchar_t* prefix) {
    return wcsncmp(s, prefix, wcslen(prefix)) == 0;
}

static const wchar_t* after_equals(const wchar_t* s) {
    const wchar_t* p = wcschr(s, L'=');
    return p ? p + 1 : L"";
}

static wchar_t* port_from_addr(const wchar_t* s) {
    const wchar_t* colon = wcsrchr(s, L':');
    return xwcsdup(colon ? colon + 1 : s);
}

static wchar_t* env_or_dup(const wchar_t* name, const wchar_t* fallback) {
    DWORD n = GetEnvironmentVariableW(name, NULL, 0);
    if (n == 0) return xwcsdup(fallback);
    wchar_t* buf = (wchar_t*)malloc(n * sizeof(wchar_t));
    if (!buf) die_alloc();
    GetEnvironmentVariableW(name, buf, n);
    return buf;
}

static wchar_t* default_datadir(void) {
    DWORD n = GetEnvironmentVariableW(L"LIQUID_SIGNET_DATADIR", NULL, 0);
    if (n) {
        wchar_t* buf = (wchar_t*)malloc(n * sizeof(wchar_t));
        if (!buf) die_alloc();
        GetEnvironmentVariableW(L"LIQUID_SIGNET_DATADIR", buf, n);
        return buf;
    }
    n = GetEnvironmentVariableW(L"LOCALAPPDATA", NULL, 0);
    const wchar_t* suffix = L"\\Bitwindow\\elements-v1";
    if (n == 0) return xwcsdup(L".\\elements-v1");
    wchar_t* base = (wchar_t*)malloc((n + wcslen(suffix) + 1) * sizeof(wchar_t));
    if (!base) die_alloc();
    GetEnvironmentVariableW(L"LOCALAPPDATA", base, n);
    wcscat(base, suffix);
    return base;
}

static void add_arg(StrBuf* cmd, const wchar_t* arg) {
    sb_add_ch(cmd, L' ');
    quote_arg(cmd, arg);
}

static void add_kv(StrBuf* cmd, const wchar_t* key, const wchar_t* value) {
    StrBuf tmp;
    sb_init(&tmp);
    sb_add(&tmp, key);
    sb_add(&tmp, value);
    add_arg(cmd, tmp.data);
    free(tmp.data);
}

int wmain(void) {
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return 111;

    wchar_t module[MAX_PATH * 4];
    if (!GetModuleFileNameW(NULL, module, (DWORD)(sizeof(module) / sizeof(module[0])))) return 112;
    wchar_t* slash = wcsrchr(module, L'\\');
    if (slash) slash[1] = 0;

    StrBuf exe;
    sb_init(&exe);
    sb_add(&exe, module);
    sb_add(&exe, L"elementsd.exe");

    wchar_t* datadir = default_datadir();
    wchar_t* rpcport = env_or_dup(L"LIQUID_SIGNET_RPCPORT", L"7045");
    wchar_t* p2pport = env_or_dup(L"LIQUID_SIGNET_P2PPORT", L"7046");
    wchar_t* mainhost = env_or_dup(L"LIQUID_SIGNET_MAINCHAIN_RPC_HOST", L"127.0.0.1");
    wchar_t* mainport = env_or_dup(L"LIQUID_SIGNET_MAINCHAIN_RPC_PORT", L"38332");
    wchar_t* mainuser = env_or_dup(L"LIQUID_SIGNET_MAINCHAIN_RPC_USER", L"user");
    wchar_t* mainpass = env_or_dup(L"LIQUID_SIGNET_MAINCHAIN_RPC_PASSWORD", L"password");
    wchar_t* cookie = env_or_dup(L"LIQUID_SIGNET_MAINCHAIN_RPC_COOKIEFILE", L"");

    StrBuf pass;
    sb_init(&pass);

    for (int i = 1; i < argc; ++i) {
        wchar_t* a = argv[i];
        if ((!wcscmp(a, L"--datadir") || !wcscmp(a, L"-datadir")) && i + 1 < argc) {
            free(datadir);
            datadir = xwcsdup(argv[++i]);
        } else if (starts_with(a, L"--datadir=") || starts_with(a, L"-datadir=")) {
            free(datadir);
            datadir = xwcsdup(after_equals(a));
        } else if ((!wcscmp(a, L"--rpc-addr") || !wcscmp(a, L"-rpc-addr") || !wcscmp(a, L"--rpc-port") || !wcscmp(a, L"-rpc-port")) && i + 1 < argc) {
            free(rpcport);
            rpcport = port_from_addr(argv[++i]);
        } else if (starts_with(a, L"--rpc-addr=") || starts_with(a, L"-rpc-addr=") || starts_with(a, L"--rpc-port=") || starts_with(a, L"-rpc-port=")) {
            free(rpcport);
            rpcport = port_from_addr(after_equals(a));
        } else if ((!wcscmp(a, L"--net-addr") || !wcscmp(a, L"-net-addr")) && i + 1 < argc) {
            free(p2pport);
            p2pport = port_from_addr(argv[++i]);
        } else if (starts_with(a, L"--net-addr=") || starts_with(a, L"-net-addr=")) {
            free(p2pport);
            p2pport = port_from_addr(after_equals(a));
        } else if ((!wcscmp(a, L"--mainchain-rpc-host") || !wcscmp(a, L"-mainchain-rpc-host")) && i + 1 < argc) {
            free(mainhost);
            mainhost = xwcsdup(argv[++i]);
        } else if (starts_with(a, L"--mainchain-rpc-host=") || starts_with(a, L"-mainchain-rpc-host=")) {
            free(mainhost);
            mainhost = xwcsdup(after_equals(a));
        } else if ((!wcscmp(a, L"--mainchain-rpc-port") || !wcscmp(a, L"-mainchain-rpc-port")) && i + 1 < argc) {
            free(mainport);
            mainport = xwcsdup(argv[++i]);
        } else if (starts_with(a, L"--mainchain-rpc-port=") || starts_with(a, L"-mainchain-rpc-port=")) {
            free(mainport);
            mainport = xwcsdup(after_equals(a));
        } else if ((!wcscmp(a, L"--mainchain-rpc-cookiefile") || !wcscmp(a, L"-mainchain-rpc-cookiefile")) && i + 1 < argc) {
            free(cookie);
            cookie = xwcsdup(argv[++i]);
        } else if (starts_with(a, L"--mainchain-rpc-cookiefile=") || starts_with(a, L"-mainchain-rpc-cookiefile=")) {
            free(cookie);
            cookie = xwcsdup(after_equals(a));
        } else if ((!wcscmp(a, L"--mainchain-grpc-url") || !wcscmp(a, L"--log-level") || !wcscmp(a, L"--log-level-file") || !wcscmp(a, L"--network") || !wcscmp(a, L"--mnemonic-seed-phrase-path")) && i + 1 < argc) {
            ++i;
        } else if (starts_with(a, L"--mainchain-grpc-url=") || starts_with(a, L"--log-level=") || starts_with(a, L"--log-level-file=") || starts_with(a, L"--network=") || starts_with(a, L"--mnemonic-seed-phrase-path=") || !wcscmp(a, L"--headless")) {
            continue;
        } else {
            add_arg(&pass, a);
        }
    }

    CreateDirectoryW(datadir, NULL);

    StrBuf cmd;
    sb_init(&cmd);
    quote_arg(&cmd, exe.data);
    add_arg(&cmd, L"-chain=elements");
    add_kv(&cmd, L"-datadir=", datadir);
    add_arg(&cmd, L"-rpcbind=127.0.0.1");
    add_arg(&cmd, L"-rpcallowip=127.0.0.1");
    add_kv(&cmd, L"-rpcport=", rpcport);
    add_kv(&cmd, L"-port=", p2pport);
    add_arg(&cmd, L"-server=1");
    add_arg(&cmd, L"-txindex=1");
    add_arg(&cmd, L"-listenonion=0");
    add_kv(&cmd, L"-mainchainrpchost=", mainhost);
    add_kv(&cmd, L"-mainchainrpcport=", mainport);
    if (cookie[0]) {
        add_kv(&cmd, L"-mainchainrpccookiefile=", cookie);
    } else {
        add_kv(&cmd, L"-mainchainrpcuser=", mainuser);
        add_kv(&cmd, L"-mainchainrpcpassword=", mainpass);
    }
    if (pass.len > 0) {
        sb_add(&cmd, pass.data);
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    BOOL ok = CreateProcessW(NULL, cmd.data, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    if (!ok) {
        fwprintf(stderr, L"failed to start %ls (error %lu)\n", exe.data, GetLastError());
        return 1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)code;
}
WRAPPER

x86_64-w64-mingw32-gcc -O2 -municode -Wall -Wextra -o "$OUT/liquid-signet.exe" "$OUT/liquid-signet.c" -lshell32
x86_64-w64-mingw32-strip "$OUT/liquid-signet.exe"
rm "$OUT/liquid-signet.c"

cat > "$OUT/liquid-signet.cmd" <<'CMD'
@echo off
setlocal
"%~dp0liquid-signet.exe" %*
exit /b %ERRORLEVEL%
CMD

cat > "$OUT/BUILD_INFO.txt" <<EOF
liquid-drivechain-signet-adaptation Windows x86_64 build
repo: https://github.com/ekulkisnek/liquid-drivechain-signet-adaptation
commit: $SHA
platform: x86_64-w64-mingw32
source tree status: clean before build
depends: make -C depends HOST=x86_64-w64-mingw32 NO_QT=1 NO_UPNP=1 NO_NATPMP=1 NO_ZMQ=1 NO_QR=1 NO_BDB=1 -j$JOBS
configure: CONFIG_SITE=$REPO/depends/x86_64-w64-mingw32/share/config.site ./configure --prefix=/ --without-gui --disable-tests --disable-bench --disable-man --disable-ccache --with-daemon=yes --with-utils=yes --with-libs=no --enable-wallet --with-sqlite=yes --without-bdb
make: make -C src -j$JOBS elementsd.exe elements-cli.exe
notes: GUI, bench, manpages, BDB, ZMQ, UPnP, and NAT-PMP were not built. WSL Win32 execution was disabled during configure/build as recommended by doc/build-windows.md.
EOF

cd "$ARTIFACT_DIR"
zip -qr "$ZIPFILE" "$(basename "$OUT")"

echo "artifact=$ZIPFILE"
sha256sum "$ZIPFILE"
stat -c '%s' "$ZIPFILE"
unzip -l "$ZIPFILE"

echo "git_status_end=$(git status --short | wc -l)"
