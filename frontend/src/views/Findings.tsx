import { useMemo, useState } from 'react';
import { Empty, SectionHead, State, TextList } from '../components/Elements';
import type { Finding, Report } from '../types';
import { findingPresentation, t } from '../i18n';

const severities = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export function Findings({ report }: { report: Report }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('ALL');
  const [category, setCategory] = useState('ALL');
  const [confidence, setConfidence] = useState('ALL');
  const [selectedID, setSelectedID] = useState<string | null>(null);
  const categories = useMemo(() => [...new Set(report.findings.map((finding) => finding.category))].sort(), [report.findings]);
  const filtered = report.findings.filter((finding) => {
    const text = `${finding.rule_id} ${finding.observation} ${finding.target}`.toLowerCase();
    return (severity === 'ALL' || finding.severity === severity) && (category === 'ALL' || finding.category === category) &&
      (confidence === 'ALL' || finding.confidence === confidence) && text.includes(query.toLowerCase().trim());
  });
  const selected = filtered.find((finding) => finding.finding_id === selectedID) ?? filtered[0];
  return <>
    <section className="section-block findings-intro"><SectionHead title="Evidence-backed findings" detail="Each item separates what was observed from what can be inferred. Status here is observed in this single scan; changes between scans belong in the diff." />
      <div className="filter-row">
        <label className="search-field">{t('Search findings')}<input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t('Rule, observation, target')} /></label>
        <label>{t('Severity')}<select value={severity} onChange={(event) => setSeverity(event.target.value)}>{severities.map((item) => <option key={item} value={item}>{item === 'ALL' ? t('All severities') : item}</option>)}</select></label>
        <label>{t('Category')}<select value={category} onChange={(event) => setCategory(event.target.value)}><option value="ALL">{t('All categories')}</option>{categories.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
        <label>{t('Confidence')}<select value={confidence} onChange={(event) => setConfidence(event.target.value)}><option value="ALL">{t('All confidence')}</option>{['HIGH', 'MEDIUM', 'LOW'].map((item) => <option key={item}>{item}</option>)}</select></label>
      </div>
      <p className="filter-count" aria-live="polite">{t('Showing')} {filtered.length} {t('of')} {report.findings.length} {t('observed findings')}</p>
    </section>
    {filtered.length === 0 ? <Empty title={report.findings.length === 0 ? 'No findings recorded' : 'No matching findings'} detail={report.findings.length === 0 ? 'An empty finding list is not proof of security. Check scan coverage and limitations.' : 'Change a filter or search term to see more results.'} /> :
      <div className="findings-layout">
        <div className="finding-list" role="list" aria-label={t('Findings')}>{filtered.map((finding) => <div role="listitem" key={finding.finding_id}>
          <button type="button" className={`finding-row${selected?.finding_id === finding.finding_id ? ' is-selected' : ''}`} aria-pressed={selected?.finding_id === finding.finding_id} onClick={() => setSelectedID(finding.finding_id)}>
            <span className={`severity severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span>
            <strong>{finding.rule_id}</strong><span>{findingPresentation(finding).finding.observation}</span>
            {findingPresentation(finding).fallback && <small>{t('Finding translation unavailable because rule version or text differs from the shipped catalog.')}</small>}
            <small>{finding.category} · {finding.confidence} {t('confidence')}</small>
          </button>
        </div>)}</div>
        <div className="finding-detail">{selected && <FindingDetail finding={selected} />}</div>
      </div>}
  </>;
}

function FindingDetail({ finding }: { finding: Finding }) {
  const shown = findingPresentation(finding);
  const detail = shown.finding;
  return <article className="detail-panel" aria-label={`${t('Finding')} ${finding.rule_id}`}>
    <div className="detail-head"><div><span className="detail-label">{t('Finding detail')}</span><h2>{finding.rule_id}</h2></div><span className={`severity severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span></div>
    <div className="detail-meta"><span>{t('Rule')} v{finding.rule_version}</span><span>{finding.category}</span><span>{finding.confidence} {t('confidence')}</span><span>{t('Observed')}</span></div>
    {shown.fallback && <div className="inline-warning" role="note">{t('Finding translation unavailable because rule version or text differs from the shipped catalog.')}</div>}
    <div className="detail-section"><h3>{t('Observation')}</h3><p>{detail.observation}</p></div>
    <div className="detail-section"><h3>{t('Evidence')}</h3><ul className="evidence-refs">{finding.evidence.map((item, index) => <li key={`${item.exchange_id}-${index}`}><State value={item.source} /> <code>{item.code}</code><small>{t('Exchange')} {item.exchange_id}</small></li>)}</ul></div>
    <div className="detail-section"><h3>{t('What it may mean')}</h3><p>{detail.inference || t('No further inference recorded.')}</p></div>
    <div className="detail-section"><h3>{t('Why it matters')}</h3><p>{detail.impact || t('Impact was not established by this observation.')}</p></div>
    <div className="detail-section"><h3>{t('What this does not prove')}</h3>{shown.fallback ? <ul className="text-list">{detail.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul> : <TextList values={detail.limitations} empty="No additional limitation was recorded for this finding." />}</div>
    <div className="detail-section"><h3>{t('Hypothesis')}</h3><p>{detail.hypothesis || t('No hypothesis recorded.')}</p></div>
    <div className="detail-section remediation"><h3>{t('Remediation')}</h3><p>{detail.remediation}</p></div>
    {finding.references.length > 0 && <div className="detail-section"><h3>{t('References')}</h3><ul className="text-list">{finding.references.map((reference, index) => <li key={index}><code>{reference}</code></li>)}</ul></div>}
  </article>;
}
