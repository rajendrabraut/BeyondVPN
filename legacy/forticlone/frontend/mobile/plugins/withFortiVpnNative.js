const fs = require('fs');
const path = require('path');
const { withAndroidManifest, withDangerousMod, withMainApplication } = require('@expo/config-plugins');

const PACKAGE_NAME = 'com.forticlone.vpn';
const MODULE_IMPORT = `${PACKAGE_NAME}.FortiVpnPackage`;

const SERVICE_SOURCE = `package ${PACKAGE_NAME};

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

    String[] lines = lastConfig.split("\\\\r?\\\\n");
    List<String> dnsEntries = new ArrayList<>();

    for (String rawLine : lines) {
      String line = rawLine == null ? "" : rawLine.trim();
      if (line.isEmpty() || line.startsWith("#")) {
        continue;
      }

      String lower = line.toLowerCase(Locale.US);
      if (lower.startsWith("remote ")) {
        String[] parts = line.split("\\\\s+");
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
`;

const MODULE_SOURCE = `package ${PACKAGE_NAME};

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.net.Uri;
import androidx.core.content.FileProvider;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableMap;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

public class FortiVpnModule extends ReactContextBaseJavaModule {
  private static final String OPENVPN_PACKAGE = "de.blinkt.openvpn";
  private static final String WIREGUARD_PACKAGE = "com.wireguard.android";

  public FortiVpnModule(ReactApplicationContext reactContext) {
    super(reactContext);
  }

  @NonNull
  @Override
  public String getName() {
    return "FortiVpnModule";
  }

  @ReactMethod
  public void getStatus(Promise promise) {
    WritableMap map = Arguments.createMap();
    map.putBoolean("available", true);
    map.putBoolean("running", FortiVpnService.isRunning);
    map.putString("profileId", FortiVpnService.lastProfileId);
    map.putString("protocol", FortiVpnService.lastProtocol);
    map.putBoolean("permissionReady", VpnService.prepare(getReactApplicationContext()) == null);
    map.putBoolean("hasConfig", FortiVpnService.lastConfig != null && !FortiVpnService.lastConfig.isEmpty());
    map.putString("remoteHost", FortiVpnService.lastRemoteHost);
    map.putString("dnsTarget", FortiVpnService.lastDnsTarget);
    map.putString("engineMode", FortiVpnService.lastEngineMode);
    map.putMap("clients", buildClientMap());
    promise.resolve(map);
  }

  private boolean isPackageInstalled(String packageName) {
    try {
      getReactApplicationContext().getPackageManager().getPackageInfo(packageName, 0);
      return true;
    } catch (Exception ignored) {
      return false;
    }
  }

  private WritableMap buildClientMap() {
    WritableMap map = Arguments.createMap();
    map.putBoolean("openvpn", isPackageInstalled(OPENVPN_PACKAGE));
    map.putBoolean("wireguard", isPackageInstalled(WIREGUARD_PACKAGE));
    return map;
  }

  private File ensureExportFile() throws Exception {
    String extension = "wireguard".equalsIgnoreCase(FortiVpnService.lastProtocol) ? ".conf" : ".ovpn";
    File exportDir = new File(getReactApplicationContext().getCacheDir(), "vpn-export");
    if (!exportDir.exists()) {
      exportDir.mkdirs();
    }

    File exportFile = new File(exportDir, FortiVpnService.lastProfileId + extension);
    FileOutputStream stream = new FileOutputStream(exportFile, false);
    stream.write(FortiVpnService.lastConfig.getBytes(StandardCharsets.UTF_8));
    stream.close();
    return exportFile;
  }

  @ReactMethod
  public void preparePermission(Promise promise) {
    Activity activity = getCurrentActivity();
    Intent intent = VpnService.prepare(getReactApplicationContext());

    if (intent == null) {
      promise.resolve(true);
      return;
    }

    if (activity == null) {
      promise.resolve(false);
      return;
    }

    activity.startActivity(intent);
    promise.resolve(false);
  }

  @ReactMethod
  public void configureProfile(String profileId, String protocol, String config, Promise promise) {
    Intent intent = new Intent(getReactApplicationContext(), FortiVpnService.class);
    intent.setAction("CONFIGURE");
    intent.putExtra("profileId", profileId);
    intent.putExtra("protocol", protocol);
    intent.putExtra("config", config);
    getReactApplicationContext().startService(intent);
    promise.resolve(true);
  }

  @ReactMethod
  public void startVpn(String profileId, String protocol, Promise promise) {
    if (VpnService.prepare(getReactApplicationContext()) != null) {
      promise.reject("permission_required", "VPN permission has not been granted yet.");
      return;
    }

    Intent intent = new Intent(getReactApplicationContext(), FortiVpnService.class);
    intent.setAction("START");
    intent.putExtra("profileId", profileId);
    intent.putExtra("protocol", protocol);
    intent.putExtra("config", FortiVpnService.lastConfig);
    getReactApplicationContext().startService(intent);
    promise.resolve(true);
  }

  @ReactMethod
  public void stopVpn(Promise promise) {
    Intent intent = new Intent(getReactApplicationContext(), FortiVpnService.class);
    intent.setAction("STOP");
    getReactApplicationContext().startService(intent);
    promise.resolve(true);
  }

  @ReactMethod
  public void shareProfile(Promise promise) {
    Activity activity = getCurrentActivity();
    if (activity == null) {
      promise.resolve(false);
      return;
    }

    if (FortiVpnService.lastConfig == null || FortiVpnService.lastConfig.isEmpty()) {
      promise.resolve(false);
      return;
    }

    try {
      File exportFile = ensureExportFile();
      Uri uri = FileProvider.getUriForFile(getReactApplicationContext(), getReactApplicationContext().getPackageName() + ".provider", exportFile);
      Intent sendIntent = new Intent(Intent.ACTION_SEND);
      sendIntent.setType("*/*");
      sendIntent.putExtra(Intent.EXTRA_STREAM, uri);
      sendIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

      Intent chooser = Intent.createChooser(sendIntent, "Open VPN profile with");
      activity.startActivity(chooser);
      promise.resolve(true);
    } catch (Exception exception) {
      promise.reject("share_failed", exception);
    }
  }

  @ReactMethod
  public void importProfileToClient(String client, Promise promise) {
    Activity activity = getCurrentActivity();
    if (activity == null) {
      promise.resolve(false);
      return;
    }

    if (FortiVpnService.lastConfig == null || FortiVpnService.lastConfig.isEmpty()) {
      promise.resolve(false);
      return;
    }

    String packageName = "";
    if ("openvpn".equalsIgnoreCase(client)) {
      packageName = OPENVPN_PACKAGE;
    } else if ("wireguard".equalsIgnoreCase(client)) {
      packageName = WIREGUARD_PACKAGE;
    }

    if (packageName.isEmpty() || !isPackageInstalled(packageName)) {
      promise.resolve(false);
      return;
    }

    try {
      File exportFile = ensureExportFile();
      Uri uri = FileProvider.getUriForFile(getReactApplicationContext(), getReactApplicationContext().getPackageName() + ".provider", exportFile);
      Intent sendIntent = new Intent(Intent.ACTION_SEND);
      sendIntent.setPackage(packageName);
      sendIntent.setType("*/*");
      sendIntent.putExtra(Intent.EXTRA_STREAM, uri);
      sendIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

      PackageManager packageManager = getReactApplicationContext().getPackageManager();
      if (sendIntent.resolveActivity(packageManager) == null) {
        promise.resolve(false);
        return;
      }

      activity.startActivity(sendIntent);
      promise.resolve(true);
    } catch (Exception exception) {
      promise.reject("import_failed", exception);
    }
  }
}
`;

const PACKAGE_SOURCE = `package ${PACKAGE_NAME};

import com.facebook.react.ReactPackage;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.uimanager.ViewManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class FortiVpnPackage implements ReactPackage {
  @Override
  public List<NativeModule> createNativeModules(ReactApplicationContext reactContext) {
    List<NativeModule> modules = new ArrayList<>();
    modules.add(new FortiVpnModule(reactContext));
    return modules;
  }

  @Override
  public List<ViewManager> createViewManagers(ReactApplicationContext reactContext) {
    return Collections.emptyList();
  }
}
`;

function ensureSourceFiles(projectRoot) {
  const base = path.join(projectRoot, 'plugins', 'android-src', 'com', 'forticlone', 'vpn');
  fs.mkdirSync(base, { recursive: true });
  fs.writeFileSync(path.join(base, 'FortiVpnService.java'), SERVICE_SOURCE);
  fs.writeFileSync(path.join(base, 'FortiVpnModule.java'), MODULE_SOURCE);
  fs.writeFileSync(path.join(base, 'FortiVpnPackage.java'), PACKAGE_SOURCE);
  const xmlDir = path.join(projectRoot, 'plugins', 'android-src', 'res', 'xml');
  fs.mkdirSync(xmlDir, { recursive: true });
  fs.writeFileSync(
    path.join(xmlDir, 'forti_vpn_file_paths.xml'),
    '<paths><cache-path name="vpn-export" path="vpn-export/" /></paths>'
  );
}

function copySourcesToAndroid(projectRoot) {
  const sourceDir = path.join(projectRoot, 'plugins', 'android-src', 'com', 'forticlone', 'vpn');
  const targetDir = path.join(projectRoot, 'android', 'app', 'src', 'main', 'java', 'com', 'forticlone', 'vpn');
  if (!fs.existsSync(sourceDir)) {
    return;
  }

  fs.mkdirSync(targetDir, { recursive: true });
  for (const file of ['FortiVpnService.java', 'FortiVpnModule.java', 'FortiVpnPackage.java']) {
    fs.copyFileSync(path.join(sourceDir, file), path.join(targetDir, file));
  }

  const resSource = path.join(projectRoot, 'plugins', 'android-src', 'res', 'xml', 'forti_vpn_file_paths.xml');
  const resTargetDir = path.join(projectRoot, 'android', 'app', 'src', 'main', 'res', 'xml');
  fs.mkdirSync(resTargetDir, { recursive: true });
  fs.copyFileSync(resSource, path.join(resTargetDir, 'forti_vpn_file_paths.xml'));
}

function addPackageToMainApplication(src) {
  if (src.includes('add(FortiVpnPackage())') || src.includes('add(new FortiVpnPackage())')) {
    return src;
  }

  let next = src;
  const importLine = 'import com.forticlone.vpn.FortiVpnPackage';
  if (!next.includes(importLine)) {
    if (next.includes('package com.forticlone.vpn')) {
      next = next.replace('package com.forticlone.vpn', `package com.forticlone.vpn\n\n${importLine}`);
    } else {
      next = next.replace(/package .*?\n/, (match) => `${match}\n${importLine}\n`);
    }
  }

  if (next.includes('PackageList(this).packages.apply {')) {
    next = next.replace(
      'PackageList(this).packages.apply {',
      'PackageList(this).packages.apply {\n              add(FortiVpnPackage())'
    );
  } else {
    next = next.replace(
      /return packages;/,
      'packages.add(FortiVpnPackage())\n      return packages;'
    );
  }

  return next;
}

const withFortiVpnNative = (config) => {
  config = withAndroidManifest(config, (config) => {
    config.modResults.manifest['uses-permission'] = config.modResults.manifest['uses-permission'] || [];
    const permissions = config.modResults.manifest['uses-permission'];
    const foregroundPermissionAdded = permissions.some((entry) => entry.$['android:name'] === 'android.permission.FOREGROUND_SERVICE');
    if (!foregroundPermissionAdded) {
      permissions.push({
        $: {
          'android:name': 'android.permission.FOREGROUND_SERVICE',
        },
      });
    }

    const app = config.modResults.manifest.application?.[0];
    if (!app) {
      return config;
    }

    app.service = app.service || [];
    const alreadyAdded = app.service.some((service) => service.$['android:name'] === '.FortiVpnService');
    if (!alreadyAdded) {
      app.service.push({
        $: {
          'android:name': '.FortiVpnService',
          'android:permission': 'android.permission.BIND_VPN_SERVICE',
          'android:exported': 'true',
          'android:foregroundServiceType': 'specialUse',
        },
        'intent-filter': [
          {
            action: [{ $: { 'android:name': 'android.net.VpnService' } }],
          },
        ],
      });
    }

    app.provider = app.provider || [];
    const providerAdded = app.provider.some((provider) => provider.$['android:name'] === 'androidx.core.content.FileProvider');
    if (!providerAdded) {
      app.provider.push({
        $: {
          'android:name': 'androidx.core.content.FileProvider',
          'android:authorities': `${PACKAGE_NAME}.provider`,
          'android:exported': 'false',
          'android:grantUriPermissions': 'true',
        },
        'meta-data': [
          {
            $: {
              'android:name': 'android.support.FILE_PROVIDER_PATHS',
              'android:resource': '@xml/forti_vpn_file_paths',
            },
          },
        ],
      });
    }

    return config;
  });

  config = withMainApplication(config, (config) => {
    config.modResults.contents = addPackageToMainApplication(config.modResults.contents);
    return config;
  });

  config = withDangerousMod(config, [
    'android',
    async (config) => {
      ensureSourceFiles(config.modRequest.projectRoot);
      copySourcesToAndroid(config.modRequest.projectRoot);
      return config;
    },
  ]);

  return config;
};

module.exports = withFortiVpnNative;
