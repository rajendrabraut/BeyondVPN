package com.forticlone.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class FortiVpnService extends VpnService {
  private static final String CHANNEL_ID = "forticlone_vpn_status";
  private static final int NOTIFICATION_ID = 7331;
  public static boolean isRunning = false;
  public static String lastProfileId = "";
  public static String lastProtocol = "";
  public static String lastConfig = "";
  public static String lastRemoteHost = "";
  public static String lastDnsTarget = "";
  public static String lastEngineMode = "foundation";
  private ParcelFileDescriptor tunnel;

  @Override
  public int onStartCommand(Intent intent, int flags, int startId) {
    if (intent == null) {
      return START_NOT_STICKY;
    }

    String action = intent.getAction();
    if ("STOP".equals(action)) {
      stopVpn();
      stopSelf();
      return START_NOT_STICKY;
    }

    if ("CONFIGURE".equals(action)) {
      lastProfileId = intent.getStringExtra("profileId") == null ? "" : intent.getStringExtra("profileId");
      lastProtocol = intent.getStringExtra("protocol") == null ? "" : intent.getStringExtra("protocol");
      lastConfig = intent.getStringExtra("config") == null ? "" : intent.getStringExtra("config");
      isRunning = false;
      return START_STICKY;
    }

    if ("START".equals(action)) {
      lastProfileId = intent.getStringExtra("profileId") == null ? "" : intent.getStringExtra("profileId");
      lastProtocol = intent.getStringExtra("protocol") == null ? "" : intent.getStringExtra("protocol");
      lastConfig = intent.getStringExtra("config") == null ? lastConfig : intent.getStringExtra("config");
      startFoundationTunnel();
      return START_STICKY;
    }

    return START_NOT_STICKY;
  }

  private void startFoundationTunnel() {
    try {
      if (tunnel != null) {
        tunnel.close();
      }

      parseProfileHints();
      startForeground(NOTIFICATION_ID, buildNotification());

      Builder builder = new Builder()
        .setSession("FortiClone")
        .addAddress("10.14.0.2", 32)
        .addDnsServer("1.1.1.1")
        .addRoute("10.14.0.0", 24);

      tunnel = builder.establish();
      isRunning = tunnel != null;
    } catch (Exception ignored) {
      isRunning = false;
    }
  }

  private void parseProfileHints() {
    lastRemoteHost = "";
    lastDnsTarget = "1.1.1.1";
    lastEngineMode = "foundation";

    if (lastConfig == null || lastConfig.isEmpty()) {
      return;
    }

    String[] lines = lastConfig.split("\\r?\\n");
    List<String> dnsEntries = new ArrayList<>();

    for (String rawLine : lines) {
      String line = rawLine == null ? "" : rawLine.trim();
      if (line.isEmpty() || line.startsWith("#")) {
        continue;
      }

      String lower = line.toLowerCase(Locale.US);
      if (lower.startsWith("remote ")) {
        String[] parts = line.split("\\s+");
        if (parts.length >= 2) {
          lastRemoteHost = parts[1];
        }
      } else if (lower.startsWith("endpoint =")) {
        String endpoint = line.substring(line.indexOf('=') + 1).trim();
        int colonIndex = endpoint.lastIndexOf(':');
        lastRemoteHost = colonIndex > 0 ? endpoint.substring(0, colonIndex) : endpoint;
      } else if (lower.startsWith("dns =")) {
        dnsEntries.add(line.substring(line.indexOf('=') + 1).trim());
      } else if (lower.startsWith("dhcp-option dns ")) {
        dnsEntries.add(line.substring("dhcp-option dns ".length()).trim());
      }
    }

    if (!dnsEntries.isEmpty()) {
      lastDnsTarget = String.join(", ", dnsEntries);
    }

    if (!lastRemoteHost.isEmpty()) {
      lastEngineMode = "staged";
    }
  }

  private Notification buildNotification() {
    NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      NotificationChannel channel = new NotificationChannel(
        CHANNEL_ID,
        "FortiClone VPN",
        NotificationManager.IMPORTANCE_LOW
      );
      channel.setDescription("Shows the active VPN tunnel state");
      manager.createNotificationChannel(channel);
    }

    Intent launchIntent = getPackageManager().getLaunchIntentForPackage(getPackageName());
    PendingIntent pendingIntent = launchIntent == null
      ? null
      : PendingIntent.getActivity(
          this,
          0,
          launchIntent,
          Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
            ? PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
            : PendingIntent.FLAG_UPDATE_CURRENT
        );

    Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
      ? new Notification.Builder(this, CHANNEL_ID)
      : new Notification.Builder(this);

    String protocolLabel = lastProtocol == null || lastProtocol.isEmpty()
      ? "VPN"
      : lastProtocol.toUpperCase(Locale.US);
    String content = lastRemoteHost.isEmpty()
      ? "Foundation tunnel active"
      : protocolLabel + " route staged for " + lastRemoteHost;

    builder
      .setContentTitle("FortiClone VPN")
      .setContentText(content)
      .setSmallIcon(android.R.drawable.stat_sys_warning)
      .setOngoing(true)
      .setOnlyAlertOnce(true);

    if (pendingIntent != null) {
      builder.setContentIntent(pendingIntent);
    }

    return builder.build();
  }

  private void stopVpn() {
    try {
      if (tunnel != null) {
        tunnel.close();
        tunnel = null;
      }
    } catch (Exception ignored) {
    }

    isRunning = false;
    stopForeground(true);
  }

  @Override
  public void onDestroy() {
    stopVpn();
    super.onDestroy();
  }

  @Override
  public IBinder onBind(Intent intent) {
    return super.onBind(intent);
  }
}
