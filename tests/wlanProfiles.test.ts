import { describe, expect, it } from 'vitest';
import { assessWifiPasswordStrength } from '../src/platform/windows/wlanProfiles';

describe('assessWifiPasswordStrength', () => {
  it('marks SSID-derived WPA passwords with years as easy to guess', () => {
    const strength = assessWifiPasswordStrength('ExampleOffice2024', true, 'Example Office');

    expect(strength.label).toBe('weak');
    expect(strength.break_in_difficulty).toBe('low');
    expect(strength.notes.join(' ')).toContain('SSID/network name');
    expect(strength.notes.join(' ')).toContain('calendar year');
  });

  it('keeps long random-looking passphrases as stronger', () => {
    const strength = assessWifiPasswordStrength('H9!vL2#qP7@sR4%zN8', true, 'Example Office');

    expect(strength.label).toBe('strong');
    expect(strength.break_in_difficulty).toBe('high');
  });
});
