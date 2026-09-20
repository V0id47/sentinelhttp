import type { DiffResult, Report } from './types';

function isReport(value: unknown): value is Report {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return candidate.schema_version === '1.0' && candidate.tool === 'SentinelHTTP' &&
    typeof candidate.target === 'string' && Array.isArray(candidate.requests) &&
    Array.isArray(candidate.findings) && Array.isArray(candidate.redirects) &&
    typeof candidate.score === 'object' && candidate.score !== null;
}

export async function loadReport(signal: AbortSignal): Promise<Report> {
  const response = await fetch('/api/report', { cache: 'no-store', credentials: 'omit', signal });
  if (!response.ok) throw new Error('report_unavailable');
  const data: unknown = await response.json();
  if (!isReport(data)) throw new Error('report_invalid');
  return data;
}

export async function loadDiff(signal: AbortSignal): Promise<DiffResult | null> {
  const response = await fetch('/api/diff', { cache: 'no-store', credentials: 'omit', signal });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error('diff_unavailable');
  const data: unknown = await response.json();
  if (typeof data !== 'object' || data === null) throw new Error('diff_invalid');
  const candidate = data as Record<string, unknown>;
  if (candidate.diff_version !== '1' || !Array.isArray(candidate.changes) || !Array.isArray(candidate.unknown) ||
    candidate.status !== 'comparable' && candidate.status !== 'partial' && candidate.status !== 'incomparable') {
    throw new Error('diff_invalid');
  }
  return data as DiffResult;
}
