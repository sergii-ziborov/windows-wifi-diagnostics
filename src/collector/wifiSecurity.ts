import type { WifiSecurityAssessment, WindowsWifiNetwork } from './types';

export function assessWifiNetworkSecurity(network: WindowsWifiNetwork): WifiSecurityAssessment {
  const authentication = network.authentication?.trim() ?? '';
  const encryption = network.encryption?.trim() ?? '';
  const auth = authentication.toLowerCase();
  const cipher = encryption.toLowerCase();
  const notes: string[] = [];
  const isPrinterLike = isPrinterOrDirectDevice(network);
  const nativeIe = network.native_bss?.information_elements;

  if (auth.includes('open') || cipher === 'none') {
    notes.push('No Wi-Fi password is advertised by Windows for this network.');
    notes.push('Connection traffic may be exposed unless protected by application-layer encryption.');
    return {
      posture: 'open',
      attack_difficulty: 'none',
      danger_level: 'high',
      label: 'Open network',
      summary: 'No Wi-Fi password; unsafe to join unless this is expected and isolated.',
      notes
    };
  }

  if (auth.includes('wep')) {
    notes.push('WEP is obsolete and should be treated as broken security.');
    return {
      posture: 'obsolete',
      attack_difficulty: 'low',
      danger_level: 'high',
      label: 'Obsolete WEP',
      summary: 'Legacy WEP security is unsafe by modern standards.',
      notes
    };
  }

  if (cipher.includes('tkip') || auth === 'wpa' || auth.startsWith('wpa-')) {
    notes.push('TKIP or legacy WPA is weaker than WPA2/WPA3 with CCMP/AES.');
    return {
      posture: 'weak',
      attack_difficulty: 'medium',
      danger_level: 'medium',
      label: 'Legacy WPA/TKIP',
      summary: 'Older WPA/TKIP metadata; prefer WPA2/WPA3 with CCMP/AES.',
      notes
    };
  }

  if (auth.includes('enterprise')) {
    notes.push('Enterprise security is usually stronger, but depends on certificate and identity validation.');
    return {
      posture: 'enterprise',
      attack_difficulty: 'high',
      danger_level: 'low',
      label: 'Enterprise security',
      summary: 'Enterprise mode; strength depends on correct certificate validation.',
      notes
    };
  }

  if (auth.includes('wpa3')) {
    notes.push('WPA3 is the strongest common personal Wi-Fi mode exposed by Windows metadata.');
    if (network.raw.Details?.toLowerCase().includes('h2e')) {
      notes.push('Windows reports H2E support.');
    }
    return {
      posture: 'strong',
      attack_difficulty: 'high',
      danger_level: isPrinterLike ? 'medium' : 'low',
      label: 'WPA3 protected',
      summary: isPrinterLike
        ? 'Strong Wi-Fi mode, but this looks like a directly exposed device.'
        : 'Strong modern Wi-Fi security metadata.',
      notes: withDeviceExposureNote(notes, isPrinterLike)
    };
  }

  if (auth.includes('wpa2') && (cipher.includes('ccmp') || cipher.includes('aes'))) {
    notes.push('WPA2-Personal with CCMP/AES is common baseline protection.');
    notes.push('WPA2-Personal is password-dependent: weak, reused, or SSID-derived passwords can be guessed offline after captured authentication evidence.');
    notes.push('Prefer WPA3-Personal/SAE where supported; otherwise use a long unique random passphrase and disable WPS.');
    return {
      posture: 'standard',
      attack_difficulty: 'medium',
      danger_level: isPrinterLike ? 'medium' : 'low',
      label: 'WPA2 protected',
      summary: isPrinterLike
        ? 'Standard Wi-Fi protection, but this looks like a directly exposed device.'
        : 'Password-dependent WPA2 protection; weak passwords are the real break point.',
      notes: withDeviceExposureNote(notes, isPrinterLike)
    };
  }

  if (auth.includes('wpa2') || auth.includes('wpa')) {
    notes.push('Windows reports WPA-family security, but the cipher is not clearly strong.');
    return {
      posture: 'standard',
      attack_difficulty: 'medium',
      danger_level: 'medium',
      label: 'WPA protected',
      summary: 'Protected network, but cipher metadata is not enough for a strong rating.',
      notes: withDeviceExposureNote(notes, isPrinterLike)
    };
  }

  if (nativeIe?.has_wpa && !nativeIe.has_rsn) {
    notes.push('Native BSS information elements include legacy WPA vendor metadata.');
    notes.push('This fallback comes from beacon/probe-response metadata, not netsh authentication fields.');
    return {
      posture: 'weak',
      attack_difficulty: 'medium',
      danger_level: 'medium',
      label: 'Legacy WPA IE',
      summary: 'Native BSS metadata suggests older WPA-family protection.',
      notes: withDeviceExposureNote(notes, isPrinterLike)
    };
  }

  if (nativeIe?.has_rsn) {
    notes.push('Native BSS information elements include RSN security metadata.');
    notes.push('Windows did not expose enough netsh authentication fields, so this is a conservative fallback.');
    if (nativeIe.has_he || nativeIe.has_eht) {
      notes.push('Native BSS metadata also reports modern HE/EHT capability information.');
    }
    return {
      posture: 'standard',
      attack_difficulty: 'medium',
      danger_level: isPrinterLike ? 'medium' : 'low',
      label: 'RSN protected',
      summary: isPrinterLike
        ? 'Protected BSS metadata, but this looks like a directly exposed device.'
        : 'Protected network inferred from native BSS RSN metadata.',
      notes: withDeviceExposureNote(notes, isPrinterLike)
    };
  }

  notes.push('Windows metadata is not enough to classify this network security clearly.');
  return {
    posture: 'unknown',
    attack_difficulty: 'unknown',
    danger_level: 'medium',
    label: 'Unknown security',
    summary: 'Security posture is unclear from Windows scan metadata.',
    notes: withDeviceExposureNote(notes, isPrinterLike)
  };
}

export function ensureNetworkSecurityAssessment(network: WindowsWifiNetwork): WindowsWifiNetwork {
  if (network.security_assessment) {
    return network;
  }

  return {
    ...network,
    security_assessment: assessWifiNetworkSecurity(network)
  };
}

function isPrinterOrDirectDevice(network: WindowsWifiNetwork): boolean {
  const ssid = network.ssid?.toLowerCase() ?? '';
  const hint = network.mac_enrichment?.device_hint?.toLowerCase() ?? '';

  return (
    ssid.startsWith('direct-') ||
    ssid.includes('hp-print') ||
    hint.includes('printer') ||
    hint.includes('wi-fi direct')
  );
}

function withDeviceExposureNote(notes: string[], exposedDevice: boolean): string[] {
  if (!exposedDevice) {
    return notes;
  }

  return [...notes, 'This looks like a direct device/AP exposure; treat it as more sensitive than a normal router SSID.'];
}
