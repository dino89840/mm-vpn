package com.mmvpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.Toast;

/**
 * Owns the TUN interface and the sing-box instance.
 *
 * Start:  MainActivity -> startService(ACTION_CONNECT, serverId)
 * Stop:   MainActivity -> startService(ACTION_DISCONNECT)
 */
public class MMVpnService extends VpnService {
    private static final String TAG = "MMVpnService";
    public static final String ACTION_CONNECT = "com.mmvpn.CONNECT";
    public static final String ACTION_DISCONNECT = "com.mmvpn.DISCONNECT";
    public static final String EXTRA_SERVER_ID = "server_id";

    public static volatile boolean running = false;
    public static volatile String runningServerName = "";
    public static volatile String lastError = "";

    private ParcelFileDescriptor tunPfd;
    private int tunFd = -1;
    private Object boxHandle;
    private Thread worker;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) return START_NOT_STICKY;
        String action = intent.getAction();
        if (ACTION_DISCONNECT.equals(action)) {
            stopVpn();
            stopSelf();
            return START_NOT_STICKY;
        }
        if (ACTION_CONNECT.equals(action)) {
            // Go foreground IMMEDIATELY — Android kills services that don't
            // call startForeground() within a few seconds.
            startForegroundWithNotification("Connecting...", "Starting VPN");
            String serverId = intent.getStringExtra(EXTRA_SERVER_ID);
            ServerConfig cfg = findServer(serverId);
            if (cfg == null) {
                fail("server not found");
                return START_NOT_STICKY;
            }
            startVpn(cfg);
            return START_STICKY;
        }
        return START_NOT_STICKY;
    }

    private ServerConfig findServer(String id) {
        if (id == null) return null;
        for (ServerConfig c : new ServerStore(this).all()) {
            if (c.id.equals(id)) return c;
        }
        return null;
    }

    private void startVpn(ServerConfig cfg) {
        if (running) stopVpn();
        lastError = "";
        worker = new Thread(() -> {
            try {
                // 1. TUN via VpnService.Builder
                Builder b = new Builder();
                b.setSession("MM VPN");
                b.setMtu(1500);
                b.addAddress("172.19.0.1", 30);
                b.addRoute("0.0.0.0", 0);
                b.addDnsServer("1.1.1.1"); // placeholder; real DNS flows via tun
                tunPfd = b.establish();
                if (tunPfd == null) throw new Exception("establish() returned null");
                tunFd = tunPfd.detachFd();
                Log.i(TAG, "tun fd=" + tunFd);

                // 2. sing-box config + start (in-process via libbox)
                String configJson = SingBoxManager.buildConfig(cfg);
                Log.i(TAG, "config built, starting box...");
                // Tell sing-box where it may write (cache.db etc.)
                String base = getFilesDir().getAbsolutePath();
                box.Box.setup(base, base, getCacheDir().getAbsolutePath());
                box.Protector protector = fd -> {
                    // called by sing-box for every dialed socket: bypass VPN
                    boolean ok = MMVpnService.this.protect(fd);
                    if (!ok) Log.w(TAG, "protect(" + fd + ") failed");
                };
                boxHandle = SingBoxManager.startBox(configJson, tunFd, protector);

                running = true;
                runningServerName = cfg.name;
                startForegroundWithNotification("MM VPN connected", cfg.name);
                Log.i(TAG, "vpn started: " + cfg);
            } catch (Exception e) {
                Log.e(TAG, "startVpn failed", e);
                fail(e.getClass().getSimpleName() + ": " + e.getMessage());
            } catch (Throwable t) {
                // native crashes / linkage errors land here
                Log.e(TAG, "startVpn crashed", t);
                fail(t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }, "mmvpn-starter");
        worker.start();
    }

    /** Record the failure, inform the user, and shut down cleanly. */
    private void fail(String reason) {
        lastError = reason != null ? reason : "unknown error";
        Log.e(TAG, "vpn failed: " + lastError);
        new Handler(Looper.getMainLooper()).post(() ->
                Toast.makeText(getApplicationContext(),
                        "VPN failed: " + lastError, Toast.LENGTH_LONG).show());
        startForegroundWithNotification("MM VPN failed", lastError);
        stopVpn();
        stopSelf();
    }

    private void stopVpn() {
        running = false;
        runningServerName = "";
        try {
            SingBoxManager.stopBox(boxHandle);
        } catch (Exception ignored) {}
        boxHandle = null;
        if (tunFd >= 0) {
            try {
                // we detached this fd from tunPfd; adopt + close cleanly
                ParcelFileDescriptor.adoptFd(tunFd).close();
            } catch (Exception e) {
                Log.w(TAG, "close tun fd failed", e);
            }
            tunFd = -1;
        }
        try {
            if (tunPfd != null) tunPfd.close();
        } catch (Exception ignored) {}
        tunPfd = null;
        stopForeground(true);
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        stopVpn();
        super.onRevoke();
    }

    private void startForegroundWithNotification(String title, String text) {
        String chId = "mmvpn";
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(new NotificationChannel(
                    chId, "MM VPN", NotificationManager.IMPORTANCE_LOW));
        }
        Intent i = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(
                this, 0, i, PendingIntent.FLAG_IMMUTABLE);
        Notification n = new Notification.Builder(this, chId)
                .setContentTitle(title)
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentIntent(pi)
                .build();
        startForeground(1, n);
    }
}
