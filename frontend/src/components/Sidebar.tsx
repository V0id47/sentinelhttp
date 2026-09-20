import type { View } from '../types';
import { t } from '../i18n';

export const navigation: { id: View; label: string; group: 'assessment' | 'evidence' | 'reference' }[] = [
  { id: 'overview', label: 'Overview', group: 'assessment' },
  { id: 'findings', label: 'Findings', group: 'assessment' },
  { id: 'http', label: 'HTTP', group: 'evidence' },
  { id: 'tls', label: 'TLS', group: 'evidence' },
  { id: 'headers', label: 'Headers', group: 'evidence' },
  { id: 'cookies', label: 'Cookies', group: 'evidence' },
  { id: 'csp', label: 'CSP', group: 'evidence' },
  { id: 'cors', label: 'CORS', group: 'evidence' },
  { id: 'redirects', label: 'Request journey', group: 'evidence' },
  { id: 'diff', label: 'Diff', group: 'reference' },
  { id: 'raw', label: 'Raw evidence', group: 'reference' },
  { id: 'about', label: 'About scan', group: 'reference' },
];

interface Props {
  view: View;
  onSelect: (view: View) => void;
  collapsed: boolean;
  onToggle: () => void;
  mobileOpen: boolean;
  onMobileClose: () => void;
}

export function Sidebar({ view, onSelect, collapsed, onToggle, mobileOpen, onMobileClose }: Props) {
  return <>
    {mobileOpen && <button className="nav-scrim" aria-label={t('Close navigation')} onClick={onMobileClose} />}
    <aside className={`sidebar${collapsed ? ' is-collapsed' : ''}${mobileOpen ? ' is-mobile-open' : ''}`} role={mobileOpen ? 'dialog' : undefined} aria-modal={mobileOpen || undefined} aria-label={t('Dashboard navigation')}>
      <div className="brand-row">
        <span className="brand-mark" aria-hidden="true"><span /></span>
        {!collapsed && <div className="brand-copy"><strong>SentinelHTTP</strong><small>{t('Assessment workbench')}</small></div>}
      </div>
      <button className="rail-toggle" type="button" onClick={onToggle} aria-label={t(collapsed ? 'Expand sidebar' : 'Collapse sidebar')} aria-expanded={!collapsed}>
        <span aria-hidden="true">{collapsed ? '›' : '‹'}</span><span className="rail-toggle-copy">{collapsed ? '' : t('Collapse navigation')}</span>
      </button>
      <nav aria-label={t('Report sections')}>
        {(['assessment', 'evidence', 'reference'] as const).map((group) => <div className="nav-group" key={group}>
          {!collapsed && <p className="nav-group-label">{t(group === 'assessment' ? 'Assessment' : group === 'evidence' ? 'Captured evidence' : 'Reference')}</p>}
          {navigation.filter((item) => item.group === group).map((item) => <button key={item.id} type="button"
            className={`nav-item${view === item.id ? ' is-active' : ''}`} aria-current={view === item.id ? 'page' : undefined}
            title={collapsed ? t(item.label) : undefined} onClick={() => onSelect(item.id)}>
            <span className="nav-glyph" aria-hidden="true">{glyph(item.id)}</span><span className="nav-item-label">{t(item.label)}</span>
          </button>)}
        </div>)}
      </nav>
      <div className="rail-footer">{collapsed ? 'v0.1' : t('Local report · v0.1.0')}</div>
    </aside>
  </>;
}

function glyph(view: View): string {
  const icons: Record<View, string> = {
    overview: '◫', findings: '◇', http: '↗', tls: '◈', headers: '☷', cookies: '◉',
    csp: '▦', cors: '⇄', redirects: '⇢', diff: '≠', raw: '{ }', about: 'ⓘ',
  };
  return icons[view];
}
