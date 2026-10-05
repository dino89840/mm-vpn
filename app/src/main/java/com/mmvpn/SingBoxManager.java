package com.mmvpn;

import org.json.JSONArray;
import org.json.JSONObject;

public class SingBoxManager {

    private static final String TUN_ADDRESS = "172.19.0.1/30";
    private static final int TUN_MTU = 1500;

    /**
     * Build a complete sing-box configuration.
     *
     * Android VpnService.Builder and this TUN inbound must use matching
     * address and MTU values.
     */
    public static String buildConfig(ServerConfig c) throws Exception {
        validate(c);

        JSONObject root = new JSONObject();

        root.put(
                "log",
                new JSONObject()
                        .put("level", "info")
                        .put("timestamp", true)
        );

        // -------------------------------------------------------------
        // TUN inbound
        // -------------------------------------------------------------
        JSONObject tun = new JSONObject();
        tun.put("type", "tun");
        tun.put("tag", "tun-in");

        // Must match MMVpnService.Builder.
        tun.put(
                "address",
                new JSONArray().put(TUN_ADDRESS)
        );
        tun.put("mtu", TUN_MTU);

        // Android Builder creates the routes itself.
        tun.put("auto_route", false);
        tun.put("strict_route", false);
        tun.put("stack", "gvisor");

        root.put(
                "inbounds",
                new JSONArray().put(tun)
        );

        // -------------------------------------------------------------
        // Proxy outbound
        // -------------------------------------------------------------
        JSONObject proxy = buildProxyOutbound(c);

        root.put(
                "outbounds",
                new JSONArray().put(proxy)
        );

        // -------------------------------------------------------------
        // Route all TUN traffic to proxy
        // -------------------------------------------------------------
        JSONObject route = new JSONObject();
        route.put("auto_detect_interface", true);
        route.put("final", "proxy");
        route.put("rules", new JSONArray());

        root.put("route", route);

        return root.toString();
    }

    private static void validate(ServerConfig c) throws Exception {
        if (c == null) {
            throw new Exception("Server configuration is null");
        }

        if (isEmpty(c.protocol)) {
            throw new Exception("Protocol is missing");
        }

        if (isEmpty(c.address)) {
            throw new Exception("Server address is missing");
        }

        if (c.port <= 0 || c.port > 65535) {
            throw new Exception("Invalid server port: " + c.port);
        }

        if (isEmpty(c.uuidOrPassword)) {
            throw new Exception("UUID/password is missing");
        }

        if ("reality".equalsIgnoreCase(value(c.security))
                && isEmpty(c.realityPublicKey)) {
            throw new Exception(
                    "REALITY public key is missing (pbk parameter)"
            );
        }
    }

    private static JSONObject buildProxyOutbound(ServerConfig c)
            throws Exception {
        JSONObject outbound = new JSONObject();

        outbound.put("type", c.protocol);
        outbound.put("tag", "proxy");
        outbound.put("server", c.address);
        outbound.put("server_port", c.port);

        switch (c.protocol.toLowerCase()) {
            case "vless":
                outbound.put("uuid", c.uuidOrPassword);

                if (!isEmpty(c.flow)) {
                    outbound.put("flow", c.flow);
                }

                // Xray-compatible UDP packet encoding.
                outbound.put("packet_encoding", "xudp");

                putTls(outbound, c);
                putTransport(outbound, c);
                break;

            case "vmess":
                outbound.put("uuid", c.uuidOrPassword);

                try {
                    outbound.put(
                            "alter_id",
                            Integer.parseInt(value(c.vmessAlterId))
                    );
                } catch (NumberFormatException ignored) {
                    outbound.put("alter_id", 0);
                }

                outbound.put("security", "auto");

                putTls(outbound, c);
                putTransport(outbound, c);
                break;

            case "trojan":
                outbound.put("password", c.uuidOrPassword);

                putTls(outbound, c);
                putTransport(outbound, c);
                break;

            case "shadowsocks":
                if (isEmpty(c.method)) {
                    throw new Exception(
                            "Shadowsocks encryption method is missing"
                    );
                }

                outbound.put("method", c.method);
                outbound.put("password", c.uuidOrPassword);
                break;

            default:
                throw new Exception(
                        "Unsupported protocol: " + c.protocol
                );
        }

        return outbound;
    }

    private static void putTls(JSONObject outbound, ServerConfig c)
            throws Exception {
        String security = value(c.security);

        boolean isReality =
                "reality".equalsIgnoreCase(security);

        boolean tlsEnabled =
                isReality || "tls".equalsIgnoreCase(security);

        if (!tlsEnabled) {
            return;
        }

        JSONObject tls = new JSONObject();
        tls.put("enabled", true);

        String serverName = isEmpty(c.sni)
                ? c.address
                : c.sni;

        tls.put("server_name", serverName);
        tls.put("insecure", c.allowInsecure);

        if (!isEmpty(c.alpn)) {
            JSONArray alpn = new JSONArray();

            for (String item : c.alpn.split(",")) {
                String protocol = item.trim();

                if (!protocol.isEmpty()) {
                    alpn.put(protocol);
                }
            }

            if (alpn.length() > 0) {
                tls.put("alpn", alpn);
            }
        }

        // REALITY normally requires a browser fingerprint.
        // For normal TLS, use uTLS only if fp was provided by the link.
        if (isReality || !isEmpty(c.fingerprint)) {
            JSONObject utls = new JSONObject();
            utls.put("enabled", true);
            utls.put(
                    "fingerprint",
                    isEmpty(c.fingerprint)
                            ? "chrome"
                            : c.fingerprint
            );

            tls.put("utls", utls);
        }

        if (isReality) {
            if (isEmpty(c.realityPublicKey)) {
                throw new Exception(
                        "REALITY public key is missing (pbk)"
                );
            }

            JSONObject reality = new JSONObject();
            reality.put("enabled", true);
            reality.put(
                    "public_key",
                    c.realityPublicKey
            );

            // Empty short_id can be valid for some servers.
            reality.put(
                    "short_id",
                    value(c.realityShortId)
            );

            tls.put("reality", reality);
        }

        outbound.put("tls", tls);
    }

    private static void putTransport(
            JSONObject outbound,
            ServerConfig c
    ) throws Exception {
        String type = value(c.transport).trim().toLowerCase();

        if (type.isEmpty()
                || "tcp".equals(type)
                || "raw".equals(type)) {
            // Plain TCP/raw transport needs no transport object.
            return;
        }

        JSONObject transport = new JSONObject();

        switch (type) {
            case "ws":
                transport.put("type", "ws");

                if (!isEmpty(c.path)) {
                    transport.put("path", c.path);
                }

                if (!isEmpty(c.host)) {
                    JSONObject headers = new JSONObject();
                    headers.put("Host", c.host);
                    transport.put("headers", headers);
                }

                if (c.maxEarlyData > 0) {
                    transport.put(
                            "max_early_data",
                            c.maxEarlyData
                    );

                    transport.put(
                            "early_data_header_name",
                            isEmpty(c.earlyDataHeaderName)
                                    ? "Sec-WebSocket-Protocol"
                                    : c.earlyDataHeaderName
                    );
                }
                break;

            case "grpc":
                transport.put("type", "grpc");

                if (!isEmpty(c.path)) {
                    transport.put(
                            "service_name",
                            c.path
                    );
                }
                break;

            case "httpupgrade":
                transport.put("type", "httpupgrade");

                if (!isEmpty(c.host)) {
                    transport.put("host", c.host);
                }

                if (!isEmpty(c.path)) {
                    transport.put("path", c.path);
                }
                break;

            case "http":
            case "h2":
                transport.put("type", "http");

                if (!isEmpty(c.host)) {
                    transport.put(
                            "host",
                            new JSONArray().put(c.host)
                    );
                }

                if (!isEmpty(c.path)) {
                    transport.put("path", c.path);
                }
                break;

            case "quic":
                transport.put("type", "quic");
                break;

            default:
                // Do not silently make an invalid connection appear connected.
                throw new Exception(
                        "Unsupported V2Ray transport: " + type
                );
        }

        outbound.put("transport", transport);
    }

    private static boolean isEmpty(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static String value(String value) {
        return value == null ? "" : value;
    }

    /**
     * Start sing-box.
     */
    public static Object startBox(
            String configJson,
            int tunFd,
            box.Protector protector
    ) throws Exception {
        return box.Box.start(
                configJson,
                tunFd,
                protector
        );
    }

    /**
     * Stop sing-box.
     */
    public static void stopBox(Object handle) {
        try {
            if (handle instanceof box.BoxHandle) {
                ((box.BoxHandle) handle).stop();
            }
        } catch (Exception ignored) {
        }
    }
}
