package com.mmvpn;

import org.json.JSONArray;
import org.json.JSONObject;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.ArrayList;
import java.util.List;

/** Persists servers + selected server in SharedPreferences. */
public class ServerStore {
    private static final String PREF = "mmvpn";
    private static final String KEY_SERVERS = "servers";
    private static final String KEY_SELECTED = "selected";

    private final SharedPreferences sp;

    public ServerStore(Context ctx) {
        sp = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    public List<ServerConfig> all() {
        List<ServerConfig> out = new ArrayList<>();
        try {
            JSONArray arr = new JSONArray(sp.getString(KEY_SERVERS, "[]"));
            for (int i = 0; i < arr.length(); i++) {
                out.add(ServerConfig.fromJson(arr.getJSONObject(i)));
            }
        } catch (Exception ignored) {}
        return out;
    }

    public void add(ServerConfig c) {
        List<ServerConfig> list = all();
        list.add(c);
        save(list);
        sp.edit().putString(KEY_SELECTED, c.id).apply();
    }

    public void remove(String id) {
        List<ServerConfig> list = all();
        for (int i = 0; i < list.size(); i++) {
            if (list.get(i).id.equals(id)) list.remove(i--);
        }
        save(list);
    }

    private void save(List<ServerConfig> list) {
        try {
            JSONArray arr = new JSONArray();
            for (ServerConfig c : list) arr.put(c.toJson());
            sp.edit().putString(KEY_SERVERS, arr.toString()).apply();
        } catch (Exception ignored) {}
    }

    public ServerConfig selected() {
        String id = sp.getString(KEY_SELECTED, null);
        if (id == null) return null;
        for (ServerConfig c : all()) {
            if (c.id.equals(id)) return c;
        }
        return null;
    }

    public void select(String id) {
        sp.edit().putString(KEY_SELECTED, id).apply();
    }
}
