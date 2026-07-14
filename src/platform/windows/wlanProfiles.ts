import { spawn } from 'node:child_process';
import type { WifiPasswordStrengthAssessment, WifiProfileSecretResult } from '../../collector/types';

export async function getWindowsWifiProfileSecret(options: { ssid: string }): Promise<WifiProfileSecretResult> {
  const ssid = options.ssid.trim();
  if (!ssid) {
    return emptyProfileSecret(null, 'SSID is required');
  }

  try {
    const { stdout } = await runNetsh(['wlan', 'show', 'profile', `name=${ssid}`, 'key=clear'], 8000);
    const fields = parseNetshKeyValueFields(stdout);
    const securityKey = parseSecurityKeyPresent(fields.get('Security key'));
    const password = fields.get('Key Content') ?? null;

    return {
      source: 'netsh_wlan_profile_key_clear',
      ssid,
      available: Boolean(password) || securityKey === false,
      password,
      security_key_present: securityKey,
      authentication: fields.get('Authentication') ?? null,
      key_type: fields.get('Key type') ?? null,
      strength: assessWifiPasswordStrength(password, securityKey, ssid),
      error: null
    };
  } catch (error) {
    return emptyProfileSecret(ssid, error instanceof Error ? error.message : String(error));
  }
}

function emptyProfileSecret(ssid: string | null, error: string): WifiProfileSecretResult {
  return {
    source: 'netsh_wlan_profile_key_clear',
    ssid,
    available: false,
    password: null,
    security_key_present: null,
    authentication: null,
    key_type: null,
    strength: null,
    error
  };
}

function runNetsh(args: string[], timeoutMs: number): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn('netsh.exe', args, { windowsHide: true });
    let stdout = '';
    let stderr = '';

    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`netsh command timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');

    child.stdout.on('data', (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk: string) => {
      stderr += chunk;
    });

    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) {
        resolve({ stdout, stderr });
        return;
      }

      reject(new Error(`netsh exited with code ${code}: ${stderr || stdout}`));
    });
  });
}

function parseNetshKeyValueFields(output: string): Map<string, string> {
  const fields = new Map<string, string>();
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(/^\s*([^:]+?)\s*:\s*(.*?)\s*$/);
    if (!match) {
      continue;
    }

    fields.set(match[1].trim(), match[2].trim());
  }

  return fields;
}

function parseSecurityKeyPresent(value: string | undefined): boolean | null {
  if (!value) {
    return null;
  }

  const normalized = value.trim().toLowerCase();
  if (normalized === 'present' || normalized === 'yes') {
    return true;
  }
  if (normalized === 'absent' || normalized === 'no') {
    return false;
  }

  return null;
}

export function assessWifiPasswordStrength(
  password: string | null,
  securityKeyPresent: boolean | null,
  ssid?: string | null
): WifiPasswordStrengthAssessment {
  if (securityKeyPresent === false) {
    return {
      length: 0,
      score: 0,
      label: 'none',
      break_in_difficulty: 'none',
      notes: ['Windows reports no saved Wi-Fi security key for this profile.']
    };
  }

  if (!password) {
    return {
      length: null,
      score: 0,
      label: 'unknown',
      break_in_difficulty: 'unknown',
      notes: ['The saved profile key was not returned by Windows.']
    };
  }

  const notes: string[] = [];
  const length = password.length;
  const normalizedPassword = normalizePasswordToken(password);
  const normalizedSsid = normalizePasswordToken(ssid ?? '');
  const characterClasses = [
    /[a-z]/.test(password),
    /[A-Z]/.test(password),
    /\d/.test(password),
    /[^a-zA-Z0-9]/.test(password)
  ].filter(Boolean).length;
  let score = Math.min(56, length * 4) + characterClasses * 10;

  if (length < 12) {
    score -= 24;
    notes.push('Shorter than 12 characters.');
  } else if (length >= 16) {
    score += 10;
    notes.push('Length is at least 16 characters.');
  }

  if (characterClasses <= 1) {
    score -= 18;
    notes.push('Uses only one character class.');
  } else if (characterClasses >= 3) {
    notes.push('Uses multiple character classes.');
  }

  if (/(.)\1{2,}/.test(password)) {
    score -= 10;
    notes.push('Contains repeated character runs.');
  }

  if (/password|qwerty|admin|router|internet|wifi|wireless|12345/i.test(password)) {
    score -= 22;
    notes.push('Contains a common Wi-Fi/password word or sequence.');
  }

  if (normalizedSsid.length >= 4 && normalizedPassword.includes(normalizedSsid)) {
    score -= 48;
    notes.push('Contains the SSID/network name, which makes targeted guessing much easier.');
  }

  if (/^[a-zA-Z]+\d{1,4}$/.test(password)) {
    score -= 12;
    notes.push('Looks like a word followed by a short number.');
  }

  if (/(?:19|20)\d{2}/.test(password)) {
    score -= 12;
    notes.push('Contains a calendar year, which is common in targeted password guesses.');
  }

  const boundedScore = Math.min(100, Math.max(0, Math.round(score)));
  if (notes.length === 0) {
    notes.push('No obvious local password-quality weakness detected.');
  }

  if (boundedScore >= 78) {
    return { length, score: boundedScore, label: 'strong', break_in_difficulty: 'high', notes };
  }
  if (boundedScore >= 58) {
    return { length, score: boundedScore, label: 'good', break_in_difficulty: 'medium', notes };
  }
  if (boundedScore >= 36) {
    return { length, score: boundedScore, label: 'fair', break_in_difficulty: 'medium', notes };
  }

  return { length, score: boundedScore, label: 'weak', break_in_difficulty: 'low', notes };
}

function normalizePasswordToken(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}
