import type { Report } from '../types';
import { Empty, SectionHead, State } from './Elements';
import { t } from '../i18n';

export function Journey({ report }: { report: Report }) {
  if (!report.scan_config.trace_enabled) {
    const request = report.requests.find((item) => item.id === report.primary_request_id);
    return <section className="section-block"><SectionHead title="Request journey" detail="Redirect tracing was not enabled for this scan." />
      {request ? <ol className="journey-list"><li className="journey-step"><span className="journey-index">1</span><div><strong>{request.method} {request.target}</strong><p>{t('One observed exchange')} · {request.status_code || t('No response')} · {request.protocol || t('Protocol unavailable')}</p><State value={request.result} /></div></li></ol> :
        <Empty title="No completed request" detail="The report contains no primary response to display." />}</section>;
  }
  return <section className="section-block"><SectionHead title="Request journey" detail="Attempted requests use the target-scope boundary. A next target may be blocked before a connection. URLs are redacted to origins." />
    {report.redirects.length === 0 ? <Empty title="No trace hops captured" detail="Tracing was requested, but no response hop could be recorded." /> :
      <ol className="journey-list">{report.redirects.map((hop) => {
        const request = report.requests.find((item) => item.id === hop.response_id);
        return <li className="journey-step" key={`${hop.hop_index}-${hop.response_id}`}>
          <span className="journey-index">{hop.hop_index + 1}</span>
          <div className="journey-content"><div className="journey-line"><strong>{hop.target}</strong><span className="status-code">{hop.status_code || t('No response')}</span></div>
            <p>{request?.method ?? 'GET'} · {request?.protocol || t('Protocol unavailable')} · Location {hop.location_status.replaceAll('_', ' ')}</p>
            {request && <div className="journey-detail"><span>{t('Resolved')} {request.resolution.chosen || t('Unavailable')}</span><span>{t('Peer')} {request.peer.verified ? t('verified') : request.peer.decision || t('unverified')}</span></div>}
            {hop.next_target && <p className="journey-next">{t('Location target (not necessarily requested)')}: {hop.next_target}</p>}
          </div>
        </li>;
      })}</ol>}
    <div className="journey-stop">{t('Trace stopped')}: <State value={report.redirect_stop || 'not recorded'} /></div>
  </section>;
}
