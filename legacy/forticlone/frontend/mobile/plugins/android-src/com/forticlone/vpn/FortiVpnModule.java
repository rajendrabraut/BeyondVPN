package com.forticlone.vpn;

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
