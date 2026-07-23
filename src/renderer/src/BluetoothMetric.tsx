import type { ReactNode } from 'react';

export function BluetoothMetric({
  label,
  value,
  tone = 'neutral'
}: {
  label: string;
  value: ReactNode;
  tone?: 'neutral' | 'danger';
}) {
  return (
    <article className={`panel bluetooth-metric bluetooth-metric-${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}
