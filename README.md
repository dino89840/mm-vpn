# MM VPN — Android VLESS/VMess VPN client

Minimal, honest VPN client for Android. Paste a `vless://`, `vmess://`,
`trojan://` or `ss://` link, tap connect.

## Architecture

```
 App UI (MainActivity)
   │  add server (paste link) / connect / disconnect
   ▼
 MMVpnService (Android VpnService)
   │  creates TUN interface, gets raw fd
   ▼
 libbox (sing-box, gomobile AAR, in-process)
   │  tun inbound (fd) → vless/vmess/trojan/ss outbound
   ▼
 Internet
```

- **sing-box** is built as an Android AAR via gomobile (`libbox/`).
  It runs in-process, so the TUN fd from `VpnService.Builder` is passed
  directly — no root, no separate binaries.
- Routing: global proxy with LAN + China bypass (configurable in
  `SingBoxManager.java`).

## Build

CI (`.github/workflows/build.yml`) does everything:

1. Go toolchain → `gomobile bind` → `libbox.aar`
2. Gradle → debug/release APK

Release APKs are signed with the keystore in repo secrets
(`KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD`).

## Project layout

```
 app/                  Android app (Java)
   src/main/java/com/mmvpn/
     MainActivity.java      server list + connect UI
     MMVpnService.java      VpnService, owns the TUN + box lifecycle
     SingBoxManager.java    libbox wrapper (start/stop, fd passing)
     ServerConfig.java      vless:// / vmess:// link parser
     ServerStore.java       SharedPreferences persistence
 libbox/               Go module wrapping sing-box experimental/libbox
   box.go              tiny wrapper (the real API is libbox itself)
   build_aar.sh        gomobile bind → app/libs/libbox.aar
 .github/workflows/build.yml
```

## Testing

You need a real server key. Paste it in the app, tap connect, check
`https://ifconfig.me` (or any IP checker) shows the server IP.

## Limitations (v1)

- No per-app routing rules UI (edit `SingBoxManager` route rules if needed)
- No subscription support (paste links manually)
- IPv4-first; IPv6 route is included but untested
