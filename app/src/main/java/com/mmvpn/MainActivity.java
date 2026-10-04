package com.mmvpn;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {
    private static final int REQ_VPN = 100;

    private ServerStore store;
    private ArrayAdapter<String> adapter;
    private List<ServerConfig> servers = new ArrayList<>();
    private TextView statusView;
    private Button connectBtn;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable statusTick = new Runnable() {
        @Override public void run() {
            refreshStatus();
            handler.postDelayed(this, 2000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        store = new ServerStore(this);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);

        statusView = new TextView(this);
        statusView.setTextSize(16);
        root.addView(statusView);

        connectBtn = new Button(this);
        connectBtn.setOnClickListener(v -> onConnectToggle());
        root.addView(connectBtn);

        Button addBtn = new Button(this);
        addBtn.setText("＋ Add server (paste link)");
        addBtn.setOnClickListener(v -> showAddDialog());
        root.addView(addBtn);

        TextView hint = new TextView(this);
        hint.setText("Long-press a server to delete it.");
        hint.setTextSize(12);
        root.addView(hint);

        ListView list = new ListView(this);
        adapter = new ArrayAdapter<>(this,
                android.R.layout.simple_list_item_single_choice, new ArrayList<>());
        list.setAdapter(adapter);
        list.setChoiceMode(ListView.CHOICE_MODE_SINGLE);
        list.setOnItemClickListener((p, v, pos, id) ->
                store.select(servers.get(pos).id));
        list.setOnItemLongClickListener((p, v, pos, id) -> {
            ServerConfig c = servers.get(pos);
            new AlertDialog.Builder(this)
                    .setTitle("Delete server?")
                    .setMessage(c.toString())
                    .setPositiveButton("Delete", (d, w) -> {
                        store.remove(c.id);
                        refreshList();
                    })
                    .setNegativeButton("Cancel", null)
                    .show();
            return true;
        });
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f);
        root.addView(list, lp);

        setContentView(root);
        refreshList();
    }

    @Override
    protected void onResume() {
        super.onResume();
        handler.post(statusTick);
        refreshList();
    }

    @Override
    protected void onPause() {
        handler.removeCallbacks(statusTick);
        super.onPause();
    }

    private void refreshList() {
        servers = store.all();
        List<String> names = new ArrayList<>();
        ServerConfig sel = store.selected();
        int selPos = -1;
        for (int i = 0; i < servers.size(); i++) {
            ServerConfig c = servers.get(i);
            names.add((MMVpnService.running && c.name.equals(MMVpnService.runningServerName)
                    ? "🟢 " : "") + c.toString());
            if (sel != null && sel.id.equals(c.id)) selPos = i;
        }
        adapter.clear();
        adapter.addAll(names);
        adapter.notifyDataSetChanged();
    }

    private void refreshStatus() {
        if (MMVpnService.running) {
            statusView.setText("🟢 Connected: " + MMVpnService.runningServerName);
            connectBtn.setText("Disconnect");
        } else {
            statusView.setText("⚪ Disconnected");
            connectBtn.setText("Connect");
        }
        refreshList();
    }

    private void onConnectToggle() {
        if (MMVpnService.running) {
            Intent i = new Intent(this, MMVpnService.class);
            i.setAction(MMVpnService.ACTION_DISCONNECT);
            startService(i);
            handler.postDelayed(this::refreshStatus, 500);
            return;
        }
        ServerConfig sel = store.selected();
        if (sel == null) {
            Toast.makeText(this, "Add a server first", Toast.LENGTH_SHORT).show();
            return;
        }
        Intent vpnIntent = VpnService.prepare(this);
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, REQ_VPN);
        } else {
            onVpnAllowed();
        }
    }

    private void onVpnAllowed() {
        ServerConfig sel = store.selected();
        Intent i = new Intent(this, MMVpnService.class);
        i.setAction(MMVpnService.ACTION_CONNECT);
        i.putExtra(MMVpnService.EXTRA_SERVER_ID, sel.id);
        startService(i);
        handler.postDelayed(this::refreshStatus, 1000);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN && resultCode == Activity.RESULT_OK) {
            onVpnAllowed();
        } else if (requestCode == REQ_VPN) {
            Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show();
        }
    }

    private void showAddDialog() {
        EditText input = new EditText(this);
        input.setHint("vless://… / vmess://… / trojan://… / ss://…");
        // offer clipboard content
        ClipboardManager cm = getSystemService(ClipboardManager.class);
        if (cm != null && cm.hasPrimaryClip()) {
            ClipData clip = cm.getPrimaryClip();
            if (clip != null && clip.getItemCount() > 0) {
                CharSequence t = clip.getItemAt(0).getText();
                if (t != null) input.setText(t.toString().trim());
            }
        }
        new AlertDialog.Builder(this)
                .setTitle("Add server")
                .setView(input)
                .setPositiveButton("Add", (d, w) -> {
                    try {
                        ServerConfig c = ServerConfig.parse(
                                input.getText().toString());
                        store.add(c);
                        refreshList();
                        Toast.makeText(this, "Added: " + c.name,
                                Toast.LENGTH_SHORT).show();
                    } catch (Exception e) {
                        Toast.makeText(this, "Bad link: " + e.getMessage(),
                                Toast.LENGTH_LONG).show();
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }
}
