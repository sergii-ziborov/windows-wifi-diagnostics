import type { BleHistoryAnalytics } from './bleAnalytics';
import type { RadioPresencePattern, RadioStabilityWindow } from './radioHistoryPatterns';
import type { WifiHistoryAnalytics } from './wifiHistoryAnalytics';

export function buildBluetoothHistoryReportHtml(
  analytics: BleHistoryAnalytics,
  windowLabel: string
): string {
  const activity = analytics.sessions.slice(-36).map((session) => ({
    label: timeLabel(session.observed_at_ms),
    value: session.points.length + session.system_devices.length
  }));
  const identityRows = analytics.identities.slice(0, 32).map((identity) => `
    <tr>
      <td>${escapeHtml(identity.label)}<small>${escapeHtml(identity.confidence.replaceAll('_', ' '))}</small></td>
      <td>${identity.sessionsSeen}/${identity.eligibleSessions} (${identity.scanCoveragePercent}%)</td>
      <td>${Math.round(identity.rssiMeanDbm)} dBm<small>${identity.rssiMinDbm}…${identity.rssiMaxDbm}; σ ${identity.rssiStandardDeviationDb.toFixed(1)} dB</small></td>
      <td>${identity.findingCount}${identity.highFindingCount ? `<small class="risk">${identity.highFindingCount} high</small>` : ''}</td>
    </tr>`).join('');
  return reportDocument({
    title: 'RadioChron Bluetooth history report',
    subtitle: `${windowLabel} · generated ${new Date().toLocaleString()}`,
    summary: [
      metric('Scan sessions', analytics.sessionCount),
      metric('Radio observations', analytics.observationCount),
      metric('RF identities', analytics.uniqueIdentityCount),
      metric('System devices', analytics.uniqueSystemDeviceCount),
      metric('Connected latest', analytics.connectedSystemDeviceCount),
      metric('Findings / high', `${analytics.findingCount} / ${analytics.highFindingCount}`)
    ],
    body: `
      ${chartSection('Observed Bluetooth activity', 'Radio observations plus OS inventory per real scan.', activity)}
      ${presenceSection(analytics.presenceRecords)}
      <section><h2>Identity evidence</h2>
        ${identityRows ? `<table><thead><tr><th>Identity</th><th>Scan coverage</th><th>RSSI evidence</th><th>Findings</th></tr></thead><tbody>${identityRows}</tbody></table>` : empty()}
      </section>
      <section><h2>Interpretation boundary</h2>
        <p>Coverage and stability are calculated only from retained scan sessions. “Not observed” is not proof of absence. RSSI is not physical distance, and recurrence is not a threat verdict.</p>
      </section>`
  });
}

export function buildWifiHistoryReportHtml(
  analytics: WifiHistoryAnalytics,
  windowLabel: string
): string {
  const activity = analytics.snapshots.slice(-36).map((snapshot) => ({
    label: timeLabel(snapshot.tsMs),
    value: snapshot.liveCount
  }));
  const changeRows = analytics.changes.slice(-24).reverse().map((change) => `
    <tr>
      <td>${escapeHtml(new Date(change.tsMs).toLocaleString())}</td>
      <td>+${change.appeared}</td>
      <td>−${change.disappeared}</td>
      <td>${change.signalDelta === null ? '—' : `${signed(change.signalDelta)} pp`}</td>
    </tr>`).join('');
  return reportDocument({
    title: 'RadioChron Wi-Fi history report',
    subtitle: `${windowLabel} · generated ${new Date().toLocaleString()}`,
    summary: [
      metric('Snapshots', analytics.snapshotCount),
      metric('Latest APs', analytics.latestApCount),
      metric('Live latest', `${analytics.latestLiveCount} (${analytics.liveRatio}%)`),
      metric('Strongest', analytics.strongestSignal === null ? '—' : `${analytics.strongestSignal}%`),
      metric('New ≤24h', analytics.newPresenceCount),
      metric('Stable / dormant', `${analytics.stablePresenceCount} / ${analytics.dormantPresenceCount}`)
    ],
    body: `
      ${chartSection('AP visibility timeline', 'Live APs per exact retained snapshot.', activity)}
      <div class="columns">
        ${breakdownSection('Security posture', analytics.security)}
        ${breakdownSection('Bands', analytics.bands)}
        ${breakdownSection('Manufacturers', analytics.vendors)}
        ${breakdownSection('Channels', analytics.channels)}
      </div>
      ${presenceSection(analytics.presenceRecords)}
      <section><h2>Observed changes</h2>
        ${changeRows ? `<table><thead><tr><th>Snapshot</th><th>Appeared</th><th>Not observed</th><th>Strongest Δ</th></tr></thead><tbody>${changeRows}</tbody></table>` : empty()}
      </section>
      <section><h2>Interpretation boundary</h2>
        <p>Changes reflect discrete local scans, not continuous RF uptime. Hidden or missed APs may reappear; signal percentages are collector evidence, not calibrated distance.</p>
      </section>`
  });
}

interface PresenceRow {
  label: string;
  detail: string;
  presence: RadioPresencePattern;
}

function presenceSection(rows: readonly PresenceRow[]): string {
  const body = rows.slice(0, 48).map((row) => {
    const presence = row.presence;
    return `<tr>
      <td>${escapeHtml(row.label)}<small>${escapeHtml(row.detail)}</small></td>
      <td><span class="badge ${escapeHtml(presence.presenceClass)}">${escapeHtml(presence.presenceClass)}</span><small>${escapeHtml(presence.summary)}</small></td>
      ${presence.windows.map((window) => `<td>${windowCell(window)}</td>`).join('')}
      <td>${dateLabel(presence.firstSeenMs)}<small>${dateLabel(presence.lastSeenMs)}</small></td>
    </tr>`;
  }).join('');
  return `<section><h2>Presence patterns · 1 / 7 / 30 days</h2>
    <p class="section-note">Sampled stability, weekday recurrence, new and dormant evidence.</p>
    ${body ? `<table><thead><tr><th>Item</th><th>Pattern</th><th>1d</th><th>7d</th><th>30d</th><th>First / last</th></tr></thead><tbody>${body}</tbody></table>` : empty()}
  </section>`;
}

function windowCell(window: RadioStabilityWindow): string {
  return `${window.seenSessions}/${window.eligibleSessions}<small>${window.coveragePercent}% · ${escapeHtml(window.state.replaceAll('-', ' '))}</small>`;
}

function chartSection(
  title: string,
  detail: string,
  points: Array<{ label: string; value: number }>
): string {
  if (!points.length) return `<section><h2>${escapeHtml(title)}</h2>${empty()}</section>`;
  const maximum = Math.max(1, ...points.map((point) => point.value));
  const bars = points.map((point) => `
    <div class="chart-bar" title="${escapeHtml(point.label)}: ${point.value}">
      <i style="height:${Math.max(3, Math.round((point.value / maximum) * 100))}%"></i>
      <span>${point.value}</span>
    </div>`).join('');
  return `<section><h2>${escapeHtml(title)}</h2><p class="section-note">${escapeHtml(detail)}</p>
    <div class="chart">${bars}</div>
    <div class="chart-axis"><span>${escapeHtml(points[0].label)}</span><span>${escapeHtml(points.at(-1)!.label)}</span></div>
  </section>`;
}

function breakdownSection(title: string, entries: Array<[string, number]>): string {
  const maximum = Math.max(1, ...entries.map((entry) => entry[1]));
  const rows = entries.slice(0, 8).map(([label, count]) => `
    <div class="breakdown"><span>${escapeHtml(label)}</span><i><b style="width:${Math.round((count / maximum) * 100)}%"></b></i><strong>${count}</strong></div>`).join('');
  return `<section class="compact"><h2>${escapeHtml(title)}</h2>${rows || empty()}</section>`;
}

function reportDocument(input: {
  title: string;
  subtitle: string;
  summary: string[];
  body: string;
}): string {
  return `<!doctype html><html><head><meta charset="utf-8"><style>
    @page{size:A4 landscape;margin:11mm}*{box-sizing:border-box}body{margin:0;color:#1e2418;font:10px Arial,sans-serif}
    header{border-bottom:3px solid #222a18;padding:0 0 10px}h1{margin:0;font-size:24px;letter-spacing:.04em}header p,.section-note{margin:4px 0 0;color:#67705d}
    .summary{display:grid;grid-template-columns:repeat(6,1fr);gap:7px;margin:12px 0}.metric{padding:8px;border:1px solid #c9cfbe;background:#f4f6f0}.metric span,.metric strong{display:block}.metric span{color:#67705d;font-size:8px;text-transform:uppercase}.metric strong{margin-top:3px;font-size:16px}
    section{break-inside:avoid;margin:13px 0}h2{margin:0 0 6px;font-size:13px;text-transform:uppercase}.columns{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}.compact{margin:0;padding:8px;border:1px solid #d5dacb}
    table{width:100%;border-collapse:collapse}th,td{padding:5px;border:1px solid #d5dacb;text-align:left;vertical-align:top}th{background:#222a18;color:white;font-size:8px;text-transform:uppercase}td small{display:block;margin-top:2px;color:#67705d}.risk{color:#a52a22}
    .badge{display:inline-block;padding:2px 5px;background:#e5eadc;font-size:8px;text-transform:uppercase}.badge.new{background:#e7f4d9}.badge.dormant{background:#eee4df}.badge.weekday{background:#dfeef4}
    .chart{height:75px;display:flex;gap:2px;align-items:end;padding:6px;border:1px solid #d5dacb;background:repeating-linear-gradient(0deg,#fff 0 18px,#e8ece3 19px)}.chart-bar{height:100%;min-width:4px;flex:1;display:flex;align-items:end;position:relative}.chart-bar i{width:100%;background:#6f842e}.chart-bar span{position:absolute;left:50%;top:1px;color:#4a5143;font-size:6px;transform:translateX(-50%)}.chart-axis{display:flex;justify-content:space-between;color:#67705d;font-size:8px}
    .breakdown{display:grid;grid-template-columns:120px 1fr 28px;gap:6px;align-items:center;margin:4px 0}.breakdown i{height:6px;background:#e2e6dc}.breakdown b{display:block;height:100%;background:#6f842e}.breakdown strong{text-align:right}.empty{padding:12px;border:1px dashed #c9cfbe;color:#67705d}
    footer{margin-top:12px;padding-top:7px;border-top:1px solid #c9cfbe;color:#67705d;font-size:8px}
  </style></head><body><header><h1>${escapeHtml(input.title)}</h1><p>${escapeHtml(input.subtitle)}</p></header>
    <div class="summary">${input.summary.join('')}</div>${input.body}
    <footer>RadioChron evidence report · local observations · no inferred samples or threat verdicts</footer>
  </body></html>`;
}

function metric(label: string, value: string | number): string {
  return `<div class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(String(value))}</strong></div>`;
}

function empty(): string {
  return '<p class="empty">No retained evidence in this scope.</p>';
}

function signed(value: number): string {
  return `${value > 0 ? '+' : ''}${value}`;
}

function timeLabel(value: number): string {
  return new Date(value).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function dateLabel(value: number): string {
  return new Date(value).toLocaleDateString();
}

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character] ?? character);
}
