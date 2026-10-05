package com.mmvpn;

import android.net.Uri;
import android.util.Base64;

import org.json.JSONObject;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Parses vless://, vmess://, trojan:// and ss:// share links
 * into a normalized config the app can store and feed to sing-box.
 */
public class ServerConfig {
    public String id;
    public String name;
    public String protocol; // vless | vmess | trojan | shadowsocks
    public String address;
    public int port;
    public String uuidOrPassword; // uuid for vless/vmess, password for trojan/ss
    public String transport;      // tcp | ws | grpc | (default tcp)
    public String host;           // ws host / http host
    public String path;           // ws path / grpc service name
    public String sni;            // tls server name
    public String security;       // none | tls | reality
    public String flow;           // xtls-rprx-vision
public String method;         // shadowsocks method
public String vmessAlterId;   // vmess only

// TLS / REALITY
public String realityPublicKey;
public String realityShortId;
public String fingerprint;
public String alpn;
public boolean allowInsecure;

// WebSocket early-data
public int maxEarlyData;
public String earlyDataHeaderName;


    public ServerConfig() {
        id = UUID.randomUUID().toString();
    }

    // ---- parsing ----

    public static ServerConfig parse(String link) throws Exception {
        link = link.trim();
        if (link.startsWith("vless://")) return parseVless(link);
        if (link.startsWith("vmess://")) return parseVmess(link);
        if (link.startsWith("trojan://")) return parseTrojan(link);
        if (link.startsWith("ss://")) return parseSs(link);
        throw new Exception("unsupported link (need vless://, vmess://, trojan:// or ss://)");
    }

    private static Map<String, String> queryMap(Uri uri) {
        Map<String, String> m = new HashMap<>();
        String q = uri.getEncodedQuery();
        if (q == null) return m;
        for (String kv : q.split("&")) {
            int i = kv.indexOf('=');
            if (i < 0) continue;
            try {
                m.put(URLDecoder.decode(kv.substring(0, i), "UTF-8"),
                        URLDecoder.decode(kv.substring(i + 1), "UTF-8"));
            } catch (Exception ignored) {}
        }
        return m;
    }

    private static ServerConfig parseVless(String link) throws Exception {
    // Example:
    // vless://uuid@server:443
    // ?security=reality
    // &sni=example.com
    // &fp=chrome
    // &pbk=PUBLIC_KEY
    // &sid=SHORT_ID
    // &type=tcp
    // &flow=xtls-rprx-vision
    // #ServerName

    Uri uri = Uri.parse(link);
    ServerConfig c = new ServerConfig();

    c.protocol = "vless";
    c.uuidOrPassword = uri.getUserInfo();
    c.address = uri.getHost();
    c.port = uri.getPort();

    Map<String, String> q = queryMap(uri);

    c.transport = q.getOrDefault("type", "tcp");
    if ("raw".equalsIgnoreCase(c.transport)) {
        // Newer Xray links can call normal TCP transport "raw".
        c.transport = "tcp";
    }

    c.security = q.getOrDefault("security", "none");
    c.flow = q.getOrDefault("flow", "");

    c.sni = q.getOrDefault(
            "sni",
            q.getOrDefault("serverName", "")
    );

    c.host = q.getOrDefault("host", "");

    if ("grpc".equalsIgnoreCase(c.transport)) {
        c.path = q.getOrDefault(
                "serviceName",
                q.getOrDefault("path", "")
        );
    } else {
        c.path = q.getOrDefault("path", "");
    }

    // REALITY parameters used by common VLESS share links.
    c.realityPublicKey = q.getOrDefault(
            "pbk",
            q.getOrDefault("publicKey", "")
    );

    c.realityShortId = q.getOrDefault(
            "sid",
            q.getOrDefault("shortId", "")
    );

    c.fingerprint = q.getOrDefault(
            "fp",
            q.getOrDefault("fingerprint", "")
    );

    c.alpn = q.getOrDefault("alpn", "");

    String insecure = q.getOrDefault(
            "allowInsecure",
            q.getOrDefault("insecure", "0")
    );

    c.allowInsecure =
            "1".equals(insecure)
                    || "true".equalsIgnoreCase(insecure);

    String earlyData = q.getOrDefault(
            "ed",
            q.getOrDefault("maxEarlyData", "0")
    );

    try {
        c.maxEarlyData = Integer.parseInt(earlyData);
    } catch (NumberFormatException ignored) {
        c.maxEarlyData = 0;
    }

    c.earlyDataHeaderName = q.getOrDefault(
            "eh",
            q.getOrDefault("earlyDataHeaderName", "")
    );

    String frag = uri.getFragment();
    c.name = frag != null && !frag.isEmpty()
            ? URLDecoder.decode(frag, "UTF-8")
            : c.address;

    // Validate required common fields early.
    if (c.uuidOrPassword == null || c.uuidOrPassword.trim().isEmpty()) {
        throw new Exception("VLESS UUID is missing");
    }

    if (c.address == null || c.address.trim().isEmpty()) {
        throw new Exception("VLESS server address is missing");
    }

    if (c.port <= 0 || c.port > 65535) {
        throw new Exception("Invalid VLESS server port: " + c.port);
    }

    if ("reality".equalsIgnoreCase(c.security)
            && (c.realityPublicKey == null
            || c.realityPublicKey.trim().isEmpty())) {
        throw new Exception(
                "REALITY public key is missing. The VLESS link must contain pbk="
        );
    }

    return c;
}


    private static ServerConfig parseVmess(String link) throws Exception {
        // vmess://base64(json)
        String b64 = link.substring("vmess://".length());
        byte[] raw = Base64.decode(b64, Base64.DEFAULT);
        JSONObject j = new JSONObject(new String(raw, StandardCharsets.UTF_8));
        ServerConfig c = new ServerConfig();
        c.protocol = "vmess";
        c.address = j.optString("add");
        c.port = j.optInt("port");
        c.uuidOrPassword = j.optString("id");
        c.vmessAlterId = j.optString("aid", "0");
        c.transport = j.optString("net", "tcp");
        c.security = j.optString("tls", "none");
        c.host = j.optString("host", "");
        c.path = j.optString("path", "");
        c.sni = j.optString("sni", c.host);
        c.name = j.optString("ps", c.address);
        return c;
    }

    private static ServerConfig parseTrojan(String link) throws Exception {
        // trojan://password@host:port?params#name
        Uri uri = Uri.parse(link);
        ServerConfig c = new ServerConfig();
        c.protocol = "trojan";
        c.uuidOrPassword = uri.getUserInfo();
        c.address = uri.getHost();
        c.port = uri.getPort();
        Map<String, String> q = queryMap(uri);
        c.transport = q.getOrDefault("type", "tcp");
        c.security = "tls";
        c.sni = q.getOrDefault("sni", c.address);
        c.host = q.getOrDefault("host", "");
        c.path = q.getOrDefault("path", "");
        String frag = uri.getFragment();
        c.name = frag != null && !frag.isEmpty()
                ? URLDecoder.decode(frag, "UTF-8") : c.address;
        return c;
    }

    private static ServerConfig parseSs(String link) throws Exception {
        // ss://base64(method:password)@host:port#name  (also plain form)
        ServerConfig c = new ServerConfig();
        c.protocol = "shadowsocks";
        String rest = link.substring("ss://".length());
        String name = "";
        int hi = rest.indexOf('#');
        if (hi >= 0) {
            name = URLDecoder.decode(rest.substring(hi + 1), "UTF-8");
            rest = rest.substring(0, hi);
        }
        if (!rest.contains("@")) { // whole userinfo is base64
            rest = new String(Base64.decode(rest, Base64.DEFAULT), StandardCharsets.UTF_8);
        }
        int at = rest.lastIndexOf('@');
        String userinfo = rest.substring(0, at);
        String hostport = rest.substring(at + 1);
        if (userinfo.contains(":")) {
            String[] up = userinfo.split(":", 2);
            c.method = up[0];
            c.uuidOrPassword = up[1];
        } else {
            String[] up = new String(Base64.decode(userinfo, Base64.DEFAULT),
                    StandardCharsets.UTF_8).split(":", 2);
            c.method = up[0];
            c.uuidOrPassword = up[1];
        }
        int ci = hostport.lastIndexOf(':');
        c.address = hostport.substring(0, ci);
        c.port = Integer.parseInt(hostport.substring(ci + 1));
        c.name = name.isEmpty() ? c.address : name;
        return c;
    }

    // ---- persistence ----

    public JSONObject toJson() throws Exception {
    JSONObject j = new JSONObject();

    j.put("id", id);
    j.put("name", name);
    j.put("protocol", protocol);
    j.put("address", address);
    j.put("port", port);
    j.put("secret", uuidOrPassword);

    j.put("transport", transport == null ? "" : transport);
    j.put("host", host == null ? "" : host);
    j.put("path", path == null ? "" : path);
    j.put("sni", sni == null ? "" : sni);
    j.put("security", security == null ? "" : security);
    j.put("flow", flow == null ? "" : flow);

    j.put("method", method == null ? "" : method);
    j.put("alterId", vmessAlterId == null ? "" : vmessAlterId);

    // TLS / REALITY
    j.put(
            "realityPublicKey",
            realityPublicKey == null ? "" : realityPublicKey
    );

    j.put(
            "realityShortId",
            realityShortId == null ? "" : realityShortId
    );

    j.put(
            "fingerprint",
            fingerprint == null ? "" : fingerprint
    );

    j.put("alpn", alpn == null ? "" : alpn);
    j.put("allowInsecure", allowInsecure);

    // WebSocket early data
    j.put("maxEarlyData", maxEarlyData);

    j.put(
            "earlyDataHeaderName",
            earlyDataHeaderName == null ? "" : earlyDataHeaderName
    );

    return j;
}


    public static ServerConfig fromJson(JSONObject j) {
    ServerConfig c = new ServerConfig();

    c.id = j.optString("id", c.id);
    c.name = j.optString("name", "");
    c.protocol = j.optString("protocol", "");
    c.address = j.optString("address", "");
    c.port = j.optInt("port", 0);
    c.uuidOrPassword = j.optString("secret", "");

    c.transport = j.optString("transport", "");
    c.host = j.optString("host", "");
    c.path = j.optString("path", "");
    c.sni = j.optString("sni", "");
    c.security = j.optString("security", "");
    c.flow = j.optString("flow", "");

    c.method = j.optString("method", "");
    c.vmessAlterId = j.optString("alterId", "");

    // TLS / REALITY
    c.realityPublicKey = j.optString("realityPublicKey", "");
    c.realityShortId = j.optString("realityShortId", "");
    c.fingerprint = j.optString("fingerprint", "");
    c.alpn = j.optString("alpn", "");
    c.allowInsecure = j.optBoolean("allowInsecure", false);

    // WebSocket early data
    c.maxEarlyData = j.optInt("maxEarlyData", 0);
    c.earlyDataHeaderName =
            j.optString("earlyDataHeaderName", "");

    return c;
}


    @Override
    public String toString() {
        return name + " (" + protocol + "://" + address + ":" + port + ")";
    }
}
