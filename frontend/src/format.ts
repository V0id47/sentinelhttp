import { locale, t } from './i18n';

export function readable(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === '') return t('Not captured');
  return String(value).replaceAll('_', ' ');
}

export function displayTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? t('Unknown time') : date.toLocaleString(locale());
}

export function duration(start: string, end: string): string {
  const milliseconds = new Date(end).getTime() - new Date(start).getTime();
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return t('Unavailable');
  return milliseconds < 1000 ? `${milliseconds} ms` : `${(milliseconds / 1000).toFixed(1)} s`;
}
