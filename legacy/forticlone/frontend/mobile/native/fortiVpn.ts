import { NativeModules } from 'react-native';

type NativeVpnStatus = {
  available: boolean;
  running: boolean;
  profileId: string;
  protocol: string;
  permissionReady: boolean;
  hasConfig: boolean;
  remoteHost?: string;
  dnsTarget?: string;
  engineMode?: string;
  clients?: {
    openvpn: boolean;
    wireguard: boolean;
  };
};

const nativeModule = NativeModules.FortiVpnModule as
  | {
      getStatus?: () => Promise<NativeVpnStatus>;
      preparePermission?: () => Promise<boolean>;
      configureProfile?: (profileId: string, protocol: string, config: string) => Promise<boolean>;
      startVpn?: (profileId: string, protocol: string) => Promise<boolean>;
      stopVpn?: () => Promise<boolean>;
      shareProfile?: () => Promise<boolean>;
      importProfileToClient?: (client: 'openvpn' | 'wireguard') => Promise<boolean>;
    }
  | undefined;

export async function getNativeVpnStatus(): Promise<NativeVpnStatus> {
  if (!nativeModule?.getStatus) {
    return {
      available: false,
      running: false,
      profileId: '',
      protocol: '',
      permissionReady: false,
      hasConfig: false,
      remoteHost: '',
      dnsTarget: '',
      engineMode: 'unavailable',
      clients: {
        openvpn: false,
        wireguard: false,
      },
    };
  }

  return nativeModule.getStatus();
}

export async function prepareNativeVpnPermission(): Promise<boolean> {
  if (!nativeModule?.preparePermission) {
    return false;
  }

  return nativeModule.preparePermission();
}

export async function configureNativeVpn(
  profileId: string,
  protocol: string,
  config: string
): Promise<boolean> {
  if (!nativeModule?.configureProfile) {
    return false;
  }

  return nativeModule.configureProfile(profileId, protocol, config);
}

export async function startNativeVpn(profileId: string, protocol: string): Promise<boolean> {
  if (!nativeModule?.startVpn) {
    return false;
  }

  return nativeModule.startVpn(profileId, protocol);
}

export async function stopNativeVpn(): Promise<boolean> {
  if (!nativeModule?.stopVpn) {
    return false;
  }

  return nativeModule.stopVpn();
}

export async function shareNativeVpnProfile(): Promise<boolean> {
  if (!nativeModule?.shareProfile) {
    return false;
  }

  return nativeModule.shareProfile();
}

export async function importNativeProfileToClient(
  client: 'openvpn' | 'wireguard'
): Promise<boolean> {
  if (!nativeModule?.importProfileToClient) {
    return false;
  }

  return nativeModule.importProfileToClient(client);
}
