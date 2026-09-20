import { Journey } from '../components/Journey';
import { Empty, SectionHead, State } from '../components/Elements';
import { duration, readable } from '../format';
import { primaryRequest } from '../types';
import { reportLimitation, t } from '../i18n';
import type { Report, View } from '../types';

const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;

export function Overview({ report, onView }: { report: Report; onView: (view: View) => void }) {
  const primary = primaryRequest(report);
  const count = (severity: string) => report.findings.filter((finding) => finding.severity === severity).length;
  const score = report.score;
  return <>
    <section className="overview-lead" aria-label={t('Assessment summary')}>
      <div className="score-panel">
        <div className="score-head"><span>{t(score.label)}</span><State value={score.status} tone={score.value === null ? 'warn' : 'good'} /></div>
        <div className="score-number">{score.value === null ? <span className="score-unavailable">—</span> : <>{score.value}<span>/100</span></>}</div>
        <p>{t('This score reflects only the checks performed by SentinelHTTP.')}</p>
        <div className="coverage-line"><span>{t('Evidence coverage')}</span><strong>{score.coverage_percent}%</strong></div>
        <progress value={score.coverage_percent} max="100" aria-label={t('Score evidence coverage')} />
        {score.value === null && <p className="score-note">{t('Insufficient evidence for a numeric score.')}</p>}
      </div>
      <div className="overview-summary">
        <div className="summary-heading"><span className="summary-pulse" aria-hidden="true" /> {t('Captured assessment')}</div>
        <dl className="summary-grid">
          <div><dt>{t('Final target')}</dt><dd>{readable(report.final_target)}</dd></div>
          <div><dt>{t('HTTP status')}</dt><dd>{primary?.status_code || t('Unavailable')}</dd></div>
          <div><dt>TLS</dt><dd>{t(readable(primary?.tls.version || primary?.tls.status))}</dd></div>
          <div><dt>{t('Certificate')}</dt><dd>{t(readable(primary?.tls.certificates[0]?.validity))}</dd></div>
          <div><dt>{t('Requests')}</dt><dd>{report.requests.length}</dd></div>
          <div><dt>{t('Duration')}</dt><dd>{duration(report.started_at, report.completed_at)}</dd></div>
        </dl>
        {report.truncated && <div className="inline-warning" role="note">{t('Some evidence was truncated or omitted. Review About scan before drawing conclusions.')}</div>}
      </div>
    </section>
    <section className="section-block"><SectionHead title="Findings in this report" detail="Observed configuration and behavior, with explicit confidence and limits." />
      {report.findings.length === 0 ? <Empty title="No findings recorded" detail="This does not establish that the application is secure; only the performed checks are represented." /> :
        <div className="severity-board">{severityOrder.map((severity) => <div className="severity-row" key={severity}><span className={`severity severity-${severity.toLowerCase()}`}>{severity}</span><progress max={report.findings.length} value={count(severity)} aria-label={`${severity} findings`} /><strong>{count(severity)}</strong></div>)}</div>}
      {report.findings.length > 0 && <button className="text-action" onClick={() => onView('findings')}>{t('Review all findings')} <span aria-hidden="true">↗</span></button>}
    </section>
    <Journey report={report} />
    <section className="section-block"><SectionHead title="Assessment limits" detail="Read these before treating a missing finding as absence of risk." />
      <ul className="limitation-list">{report.limitations.slice(0, 4).map((item, index) => <li key={index}>{reportLimitation(item)}</li>)}</ul>
    </section>
  </>;
}
