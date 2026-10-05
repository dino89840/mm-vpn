package com.mmvpn;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Builds the sing-box JSON config for a server, and wraps the
 * gomobile-generated box.Box API (libbox.aar).
 *
 * Java only sees: buildConfig(cfg) -> json, Box.start(...), handle.stop().
 */
public class SingBoxManager {

    /** Build the full sing-box config JSON for the given server. */
    public static String buildConfig(ServerConfig c) throws Exception {
        JSONObject root = new JSONObject();

        root.put("log", new JSONObject().put("level", "warn"));

        // --- TUN inbound (fd comes from VpnService via box.OpenTun) ---
        JSONObject tun = new JSONObject();
        tun.put("type", "tun");
        tun.put("tag", "tun-in");
        tun.put("stack", "gvisor");
        tun.put("auto_route", false);
        tun.put("strict_route", false);
        root.put("inbounds", new JSONArray().put(tun));

        // --- outbounds: just the proxy. All traffic (including DNS) goes
        // through it. No separate DNS config — simpler and more robust.
        JSONArray outbounds = new JSONArray();
        outbounds.put(buildProxyOutbound(c));
        root.put("outbounds", outbounds);

        // --- route: everything to proxy ---
        JSONObject route = new JSONObject();
        route.put("rules", new JSONArray());
        route.put("final", "proxy");
        route.put("auto_detect_interface", true);
        root.put("route", route);

        return root.toString();
    }

    private static JSONObject buildProxyOutbound(ServerConfig c) throws Exception {
        JSONObject o = new JSONObject();
        o.put("type", c.protocol);
        o.put("tag", "proxy");
        o.put("server", c.address);
        o.put("server_port", c.port);

        switch (c.protocol) {
            case "vless":
                o.put("uuid", c.uuidOrPassword);
                if (!c.flow.isEmpty()) o.put("flow", c.flow);
                putTls(o, c);
                putTransport(o, c);
                break;
            case "vmess":
                o.put("uuid", c.uuidOrPassword);
                try {
                    o.put("alter_id", Integer.parseInt(c.vmessAlterId));
                } catch (NumberFormatException e) {
                    o.put("alter_id", 0);
                }
                o.put("security", "auto");
                putTls(o, c);
                putTransport(o, c);
                break;
            case "trojan":
                o.put("password", c.uuidOrPassword);
                putTls(o, c);
                putTransport(o, c);
                break;
            case "shadowsocks":
                o.put("method", c.method);
                o.put("password", c.uuidOrPassword);
                break;
            default:
                throw new Exception("unknown protocol: " + c.protocol);
        }
        return o;
    }

    private static void putTls(JSONObject o, ServerConfig c) throws Exception {
        boolean tls = "tls".equalsIgnoreCase(c.security)
                || "reality".equalsIgnoreCase(c.security);
        if (!tls) return;
        JSONObject t = new JSONObject();
        t.put("enabled", true);
        t.put("server_name", c.sni.isEmpty() ? c.address : c.sni);
        if (!"reality".equalsIgnoreCase(c.security)) {
            JSONObject utls = new JSONObject();
            utls.put("enabled", true);
            utls.put("fingerprint", "chrome");
            t.put("utls", utls);
        }
        // NOTE: REALITY needs public_key/short_id which share links don't
        // carry — v1 supports TLS only; REALITY links will fail to connect.
        o.put("tls", t);
    }

    private static void putTransport(JSONObject o, ServerConfig c) throws Exception {
        String type = c.transport.isEmpty() ? "tcp" : c.transport;
        if ("tcp".equals(type)) return; // default, nothing to add
        JSONObject t = new JSONObject();
        t.put("type", type);
        if ("ws".equals(type)) {
            if (!c.path.isEmpty()) t.put("path", c.path);
            if (!c.host.isEmpty()) {
                t.put("headers", new JSONObject().put("Host", c.host));
            }
        } else if ("grpc".equals(type)) {
            if (!c.path.isEmpty()) t.put("service_name", c.path);
        }
        // httpupgrade / quic etc. fall through as type only (v1 best-effort)
        o.put("transport", t);
    }

    // ---- box.Box wrappers (libbox.aar must be present at compile time) ----

    /** Start sing-box. Returns an opaque handle. Throws on error. */
    public static Object startBox(String configJson, int tunFd,
                                  box.Protector protector) throws Exception {
        return box.Box.start(configJson, tunFd, protector);
    }

    public static void stopBox(Object handle) {
        try {
            if (handle instanceof box.BoxHandle) {
                ((box.BoxHandle) handle).stop();
            }
        } catch (Exception ignored) {}
    }
}
