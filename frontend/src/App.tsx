import { useEffect, useRef, useState } from 'react';
import { loadDiff, loadReport } from './api';
import { Sidebar, navigation } from './components/Sidebar';
import { displayTime } from './format';
import { initialLocale, setActiveLocale, t, type Locale } from './i18n';
import { Overview } from './views/Overview';
import { Findings } from './views/Findings';
import { EvidenceView } from './views/Evidence';
import type { DiffResult, Report, View } from './types';

export function App() {
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState(false);
  const [diff, setDiff] = useState<DiffResult | null>(null);
  const [diffError, setDiffError] = useState(false);
  const [reload, setReload] = useState(0);
  const [view, setView] = useState<View>('overview');
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [language, setLanguage] = useState<Locale>(initialLocale);
  const mobileMenuButton = useRef<HTMLButtonElement>(null);

  setActiveLocale(language);
  function changeLanguage(next: Locale) {
    setActiveLocale(next);
    setLanguage(next);
    try { localStorage.setItem('sentinelhttp.language', next); } catch { /* private browsing */ }
    document.documentElement.lang = next;
  }

  useEffect(() => { document.documentElement.lang = language; document.title = `SentinelHTTP · ${t('Assessment')}`; }, [language]);

  useEffect(() => {
    const controller = new AbortController();
    loadReport(controller.signal).then((value) => { setReport(value); setError(false); })
      .catch(() => { if (!controller.signal.aborted) setError(true); });
    loadDiff(controller.signal).then((value) => { setDiff(value); setDiffError(false); })
      .catch(() => { if (!controller.signal.aborted) setDiffError(true); });
    return () => controller.abort();
  }, [reload]);

  useEffect(() => {
    if (!mobileOpen) return;
    const buttons = [...document.querySelectorAll<HTMLButtonElement>('.sidebar button')];
    buttons[0]?.focus();
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setMobileOpen(false);
        mobileMenuButton.current?.focus();
      }
      if (event.key === 'Tab' && buttons.length > 0) {
        const first = buttons[0];
        const last = buttons[buttons.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last?.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first?.focus();
        }
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [mobileOpen]);

  function select(next: View) {
    setView(next);
    setMobileOpen(false);
    window.scrollTo({ top: 0, behavior: 'instant' });
  }

  const title = t(navigation.find((item) => item.id === view)?.label ?? 'Overview');
  return <div className={`app-shell${collapsed ? ' rail-small' : ''}`}>
    <a className="skip-link" href="#main">{t('Skip to content')}</a>
    <Sidebar view={view} onSelect={select} collapsed={collapsed} onToggle={() => setCollapsed((value) => !value)}
      mobileOpen={mobileOpen} onMobileClose={() => setMobileOpen(false)} />
    <main id="main" className="main" tabIndex={-1}>
      <header className="topbar">
        <button ref={mobileMenuButton} type="button" className="mobile-menu" aria-label={t('Open navigation')} aria-expanded={mobileOpen} onClick={() => setMobileOpen(true)}>☰</button>
        <div className="topbar-identity"><span className="product-mini">SentinelHTTP</span><span className="topbar-divider" aria-hidden="true" /><span>{t('Local assessment')}</span></div>
        <div className="topbar-status"><span className="live-dot" aria-hidden="true" /> {t('Offline report')}</div>
        <label className="language-select">{t('Language')} <select aria-label={t('Language')} value={language} onChange={(event) => changeLanguage(event.target.value as Locale)}><option value="en">English</option><option value="es">Español</option><option value="ru">Русский</option><option value="zh-CN">简体中文</option></select></label>
      </header>
      {!report && !error && <div className="load-state" role="status"><span className="spinner" aria-hidden="true" />{t('Reading validated report…')}</div>}
      {error && <div className="load-state" role="alert"><h1>{t('Report unavailable')}</h1><p>{t('The local server could not provide a valid report. Check the terminal and try again.')}</p><button className="action" onClick={() => setReload((value) => value + 1)}>{t('Retry loading')}</button></div>}
      {report && <div className="content">
        <div className="page-intro">
          <div className="report-kicker"><span className="kicker-rule" /> {t('Assessment')} / {title}</div>
          <h1>{title}</h1>
          <div className="report-meta"><span className="target-text">{report.target}</span><span>{t('Captured')} {displayTime(report.started_at)}</span></div>
        </div>
        {view === 'overview' ? <Overview report={report} onView={select} /> :
          view === 'findings' ? <Findings report={report} /> :
            <EvidenceView report={report} view={view} diff={diff} diffError={diffError} />}
        <footer className="content-footer">{t('SentinelHTTP reports observations from performed checks. Absence of findings does not prove an application is secure.')}</footer>
      </div>}
    </main>
  </div>;
}
