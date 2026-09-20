import { t } from '../i18n';
import { DefinitionList, Empty, SectionHead, State, TextList } from '../components/Elements';
import { Journey } from '../components/Journey';
import { displayTime, duration, readable } from '../format';
import { primaryRequest } from '../types';
import { reportLimitation } from '../i18n';
import type { DiffResult, Report, RequestSummary, View } from '../types';

export function EvidenceView({ report, view, diff, diffError }: { report: Report; view: View; diff: DiffResult | null; diffError: boolean }) {
  const primary = primaryRequest(report);
  switch (view) {
    case 'http': return <HTTPView report={report} primary={primary} />;
    case 'tls': return <TLSView primary={primary} />;
    case 'headers': return <HeadersView primary={primary} />;
    case 'cookies': return <CookiesView primary={primary} />;
    case 'csp': return <CSPView primary={primary} />;
    case 'cors': return <CORSView report={report} primary={primary} />;
    case 'redirects': return <Journey report={report} />;
    case 'diff': return <DiffView report={report} diff={diff} diffError={diffError} />;
    case 'raw': return <RawView report={report} />;
    case 'about': return <AboutView report={report} />;
    default: return null;
  }
}

function HTTPView({ report, primary }: { report: Report; primary?: RequestSummary }) {
  return <>
    <section className="section-block"><SectionHead title="Observed HTTP exchange" detail="Response facts from the selected primary request, without response bodies or sensitive header values." />
      {!primary ? <Empty title="No primary response" detail="The request did not complete far enough to select a primary response." /> :
        <DefinitionList items={[
          { label: 'Method', value: primary.method }, { label: 'HTTP status', value: primary.status_code || t('Unavailable') },
          { label: 'Protocol', value: readable(primary.protocol) }, { label: 'Result', value: <State value={primary.result} /> },
          { label: 'Duration', value: `${primary.duration_millis} ms` }, { label: 'Safe target', value: primary.target },
          { label: 'Peer verified', value: primary.peer.verified ? t('Yes') : readable(primary.peer.decision) },
          { label: 'Chosen IP', value: readable(primary.resolution.chosen) },
        ]} />}
    </section>
    <section className="section-block"><SectionHead title="Captured requests" detail="Each exchange used a fresh scope approval. IDs identify report evidence, not server sessions." />
      {report.requests.length === 0 ? <Empty title="No requests recorded" detail="The report contains no captured request metadata." /> :
        <div className="table-scroll"><table><caption>{t("Request metadata")}</caption><thead><tr><th scope="col">{t("Target")}</th><th scope="col">{t("Method")}</th><th scope="col">{t("Status")}</th><th scope="col">{t("Protocol")}</th><th scope="col">{t("Result")}</th><th scope="col">{t("Time")}</th></tr></thead><tbody>
          {report.requests.map((request) => <tr key={request.id}><td className="wrap-cell">{request.target}</td><td>{request.method}</td><td>{request.status_code || '—'}</td><td>{readable(request.protocol)}</td><td><State value={request.result} /></td><td>{request.duration_millis} ms</td></tr>)}
        </tbody></table></div>}
    </section>
    {primary && <section className="section-block"><SectionHead title="Resolution and peer" detail="Reported addresses are evidence from the approval step; a verified peer is the connected socket address." />
      <DefinitionList items={[{ label: 'DNS host', value: primary.resolution.host }, { label: 'Resolution source', value: primary.resolution.source }, { label: 'Policy', value: primary.resolution.policy_version }, { label: 'Expected peer', value: readable(primary.peer.expected) }, { label: 'Observed peer', value: readable(primary.peer.observed) }]} />
      {primary.resolution.addresses.length > 0 && <div className="table-scroll"><table><caption>{t("Resolved addresses")}</caption><thead><tr><th scope="col">{t("Address")}</th><th scope="col">{t("Class")}</th><th scope="col">{t("Decision")}</th></tr></thead><tbody>{primary.resolution.addresses.map((address, index) => <tr key={`${address.normalized}-${index}`}><td>{address.normalized}</td><td>{readable(address.decision.class)}</td><td><State value={address.decision.reason} tone={address.decision.allowed ? 'good' : 'warn'} /></td></tr>)}</tbody></table></div>}
    </section>}
  </>;
}

function TLSView({ primary }: { primary?: RequestSummary }) {
  if (!primary) return <Empty title="TLS evidence unavailable" detail="No primary response was selected." />;
  const tls = primary.tls;
  return <>
    <section className="section-block"><SectionHead title="Negotiated TLS" detail="This describes the connection observed during the scan, not an exhaustive cipher-suite audit." />
      <DefinitionList items={[{ label: 'Capture', value: <State value={tls.status} /> }, { label: 'Protocol', value: readable(tls.version) }, { label: 'Cipher suite', value: readable(tls.cipher_suite) }, { label: 'Application protocol', value: readable(tls.negotiated_protocol) }, { label: 'Evidence truncated', value: t(tls.truncated ? 'Yes' : 'No') }]} />
    </section>
    <section className="section-block"><SectionHead title="Certificate chain" detail="Names and issuers are untrusted text from the observed certificates." />
      {tls.certificates.length === 0 ? <Empty title="No certificate metadata" detail="The connection was not HTTPS or certificate capture was unavailable." /> : tls.certificates.map((certificate, index) => <article className="certificate" key={`${certificate.sha256}-${index}`}>
        <div className="certificate-title"><span className="certificate-index">{index === 0 ? t('Leaf') : `${t('Chain')} ${index + 1}`}</span><State value={certificate.validity} tone={certificate.validity === 'valid' ? 'good' : 'warn'} /></div>
        <DefinitionList items={[{ label: 'Subject', value: readable(certificate.subject) }, { label: 'Issuer', value: readable(certificate.issuer) }, { label: 'Valid from', value: displayTime(certificate.not_before) }, { label: 'Valid until', value: displayTime(certificate.not_after) }, { label: 'Days remaining', value: certificate.days_remaining }, { label: 'SHA-256', value: <code>{certificate.sha256}</code> }]} />
        <div className="certificate-sans"><strong>{t("Subject alternative names")}</strong>{certificate.sans.length === 0 ? <p className="muted">{t("None captured")}</p> : <ul className="chip-list">{certificate.sans.map((san, position) => <li key={`${san.kind}-${position}`}>{san.kind}: {san.value}</li>)}</ul>}</div>
      </article>)}
    </section>
  </>;
}

function HeadersView({ primary }: { primary?: RequestSummary }) {
  if (!primary) return <Empty title="Header evidence unavailable" detail="No primary response was selected; missing headers cannot be inferred." />;
  return <section className="section-block"><SectionHead title="Security header assessment" detail="Presence, applicability and effective state are separate. Raw values are not stored in this report." />
    <div className="table-scroll"><table><caption>{t("Captured security headers")}</caption><thead><tr><th scope="col">{t("Header")}</th><th scope="col">{t("Count")}</th><th scope="col">{t("Applicability")}</th><th scope="col">{t("Status")}</th><th scope="col">{t("Effective")}</th></tr></thead><tbody>
      {primary.headers.map((header) => <tr key={header.id}><th scope="row">{header.name}</th><td>{header.occurrences}</td><td>{readable(header.applicability)}</td><td><State value={header.status} tone={header.truncated ? 'warn' : undefined} /></td><td>{header.truncated ? 'Truncated' : readable(header.effective)}</td></tr>)}
    </tbody></table></div>
  </section>;
}

function CookiesView({ primary }: { primary?: RequestSummary }) {
  if (!primary) return <Empty title="Cookie evidence unavailable" detail="No primary response was selected." />;
  return <section className="section-block"><SectionHead title="Cookie policy" detail="Only cookie names and policy metadata are retained. Cookie values are never displayed." />
    <div className="capture-note"><span>{t("Capture:")} <State value={primary.cookie_capture} /></span><span>{primary.cookie_analyzed_fields} {t('of')} {primary.cookie_field_count} {t('fields analyzed')}</span>{primary.cookie_truncated && <span>{t("Some cookie evidence was truncated")}</span>}</div>
    {primary.cookies.length === 0 && (primary.cookie_capture !== 'capture_complete' || primary.cookie_truncated || primary.cookie_omitted_fields > 0) ? <Empty title="Cookie evidence incomplete" detail="No absence conclusion is possible from an unavailable or truncated cookie capture." /> : primary.cookies.length === 0 ? <Empty title="No cookies in this response" detail="This applies only to the captured response; other application paths were not assessed." /> :
      <div className="table-scroll"><table><caption>{t("Cookie metadata, without values")}</caption><thead><tr><th scope="col">{t("Name")}</th><th scope="col">{t("Secure")}</th><th scope="col">{t("HttpOnly")}</th><th scope="col">{t("SameSite")}</th><th scope="col">{t("Domain scope")}</th><th scope="col">{t("Path scope")}</th><th scope="col">{t("Assessment")}</th></tr></thead><tbody>
        {primary.cookies.map((cookie) => <tr key={`${cookie.position}-${cookie.name}`}><th scope="row">{cookie.name}</th><td>{cookie.secure ? t('On') : readable(cookie.secure_status)}</td><td>{cookie.http_only ? t('On') : readable(cookie.http_only_status)}</td><td>{readable(cookie.same_site)}</td><td>{readable(cookie.domain)}{cookie.domain_host_only ? ` (${t('host only')})` : ''}</td><td>{readable(cookie.path_scope)}</td><td>{cookie.truncated ? t('Truncated') : cookie.acceptance === 'accepted' ? cookie.session_like ? t('Session-like inference') : t('Observed policy') : readable(cookie.acceptance)}</td></tr>)}
      </tbody></table></div>}
  </section>;
}

function CSPView({ primary }: { primary?: RequestSummary }) {
  if (!primary) return <Empty title="CSP evidence unavailable" detail="No primary response was selected." />;
  const csp = primary.csp;
  return <>
    <section className="section-block"><SectionHead title="Content Security Policy" detail="Enforced and report-only policies remain separate. Weak policy is not proof of XSS." />
      <div className="capture-note"><span>{t("Capture:")} <State value={csp.capture} /></span><span>{t('Applicability')}: {readable(csp.applicability)}</span>{csp.truncated && <span>{t("Evidence truncated")}</span>}</div>
      {csp.policies.length === 0 ? <Empty title="No policies captured" detail="No complete CSP policy was available for this response." /> :
        <div className="policy-list">{csp.policies.map((policy, index) => <article className="policy" key={`${policy.disposition}-${policy.field_index}-${policy.member_index}-${index}`}>
          <div className="policy-head"><strong>{t('Policy')} {index + 1}</strong><State value={policy.disposition} tone={policy.disposition === 'enforce' ? 'good' : 'muted'} /><span>{readable(policy.parse)}</span></div>
          {policy.directives.length === 0 ? <p className="muted">{t("No parsed directives")}</p> : <div className="directive-list">{policy.directives.map((directive, position) => <div className="directive" key={`${directive.name}-${position}`}><div><strong>{directive.name}</strong><small>{readable(directive.status)}</small></div><ul className="chip-list">{directive.sources.map((source, sourceIndex) => <li className={source.keyword === 'unsafe-inline' || source.keyword === 'unsafe-eval' ? 'weak-source' : ''} key={`${source.kind}-${sourceIndex}`}>
            {source.redacted ? `[${source.kind} redacted]` : source.keyword ? `'${source.keyword}'` : source.host ? `${source.subdomain_wildcard ? '*.' : ''}${source.host}${source.port ? `:${source.port}` : ''}` : source.scheme ? `${source.scheme}:` : readable(source.kind)}
          </li>)}</ul></div>)}</div>}
        </article>)}</div>}
    </section>
    <section className="section-block"><SectionHead title="Analyzer observations" detail="These describe policy properties, not a confirmed exploit." /><TextList values={csp.observations} empty="No CSP observations recorded." /></section>
  </>;
}

function CORSView({ report, primary }: { report: Report; primary?: RequestSummary }) {
  if (!primary) return <Empty title="CORS evidence unavailable" detail="No primary response was selected." />;
  const cors = primary.cors;
  return <>
    <section className="section-block"><SectionHead title="Passive CORS observation" detail="A permissive header alone does not demonstrate authenticated data exposure." />
      {cors.capture !== 'capture_complete' || cors.truncated ? <Empty title="Passive capture incomplete" detail="A failed or truncated header capture cannot establish that a CORS policy is absent." /> : <>
        <DefinitionList items={[{ label: 'Capture', value: <State value={cors.capture} /> }, { label: 'Allowed origin', value: cors.origin_value || readable(cors.origin_kind) }, { label: 'Origin state', value: readable(cors.origin_status) }, { label: 'Credentials', value: cors.credentials_enabled ? t('Enabled') : readable(cors.credentials_status) }, { label: 'Vary: Origin', value: cors.vary_origin ? t('Observed') : readable(cors.vary_status) }, { label: 'Shared cache', value: readable(cors.cache_status) }]} />
        <TextList values={cors.observations} empty="No passive CORS observations recorded." />
      </>}
    </section>
    <section className="section-block"><SectionHead title="Controlled probe" detail="Only three fixed, uncredentialed samples are possible when probing is enabled." />
      {!report.cors_probe ? <Empty title="Probe not run" detail="The scan did not record CORS probe attempts. Passive evidence above remains available." /> :
        <div className="table-scroll"><table><caption>{t("Fixed CORS probe attempts")}</caption><thead><tr><th scope="col">{t("Sample")}</th><th scope="col">{t("Origin")}</th><th scope="col">{t("State")}</th><th scope="col">{t("HTTP")}</th><th scope="col">{t("Observed ACAO")}</th></tr></thead><tbody>
          {report.cors_probe.attempts.map((attempt, index) => <tr key={`${attempt.kind}-${index}`}><th scope="row">{readable(attempt.kind)}</th><td className="wrap-cell">{attempt.origin}</td><td><State value={attempt.state} /></td><td>{attempt.status_code || '—'}</td><td className="wrap-cell">{attempt.cors.origin_value || readable(attempt.cors.origin_kind)}</td></tr>)}
        </tbody></table></div>}
    </section>
  </>;
}

function DiffView({ report, diff, diffError }: { report: Report; diff: DiffResult | null; diffError: boolean }) {
  return <section className="section-block"><SectionHead title="Compare assessments" detail="A semantic comparison is computed by the pure diff engine from two validated local reports." />
    {diffError && <Empty title="Comparison unavailable" detail="The local server could not provide a valid comparison. Check the terminal and reopen this report." />}
    {!diffError && !diff && <div className="diff-explainer"><div className="diff-symbol" aria-hidden="true">≠</div><div><h3>{t("Open with a baseline")}</h3><p><code>{t("sentinelhttp serve new.json --compare old.json")}</code></p><p>{t("The browser never selects report files. The CLI validates both paths before the local server starts.")}</p></div></div>}
    {!diffError && diff && <>
      <div className="diff-summary"><div><span>{t("Before")}</span><strong>{displayTime(diff.before_started)}</strong></div><div className="diff-arrow" aria-hidden="true">→</div><div><span>{t("After")}</span><strong>{displayTime(diff.after_started)}</strong></div><State value={diff.status} tone={diff.status === 'comparable' ? 'good' : 'warn'} /></div>
      {diff.status === 'incomparable' && <div className="inline-warning">{t("These reports cannot establish the same initial endpoint. No remediation or regression is inferred.")}</div>}
      <div className="diff-columns"><div><h3>{t("Supported changes")} <span>{diff.changes.length}</span></h3>
        {diff.changes.length === 0 ? <Empty title="No supported change recorded" detail="This does not prove equivalence; inspect unknown sections and source reports." /> :
          <ul className="diff-list">{diff.changes.map((change, index) => <li key={`${change.kind}-${change.key}-${index}`}><State value={change.kind} tone={change.kind === 'resolved_finding' ? 'good' : change.kind === 'new_finding' ? 'warn' : undefined} /><strong>{change.key}</strong>{change.before || change.after ? <div className="diff-values"><span>{change.before || t('Not present')}</span><span aria-hidden="true">→</span><span>{change.after || t('Not present')}</span></div> : <p className="muted">{t("Captured policy changed. Inspect both source reports for details.")}</p>}</li>)}</ul>}
      </div><div><h3>{t("Unknown or limited")} <span>{diff.unknown.length}</span></h3>
        {diff.unknown.length === 0 ? <p className="muted">{t("No comparison uncertainty was recorded by this diff version.")}</p> :
          <ul className="diff-list unknown-list">{diff.unknown.map((item, index) => <li key={`${item.section}-${item.key}-${index}`}><strong>{item.section}{item.key ? ` · ${item.key}` : ''}</strong><p>{readable(item.reason)}</p></li>)}</ul>}
      </div></div>
    </>}
    <div className="inline-warning">{t("This report's initial target scope is")} <strong>{report.target_scope}</strong>{t(". Automatic comparison is limited to queryless root scans of the same origin; redacted paths cannot be matched safely.")}</div>
  </section>;
}

function RawView({ report }: { report: Report }) {
  const serialized = JSON.stringify(report, null, 2);
  const clipped = serialized.length > 200_000;
  return <section className="section-block"><SectionHead title="Minimized report JSON" detail="This is the validated report document, not raw HTTP traffic. Cookie values, bodies and full URL paths are excluded." />
    {clipped && <div className="inline-warning">{t("Preview limited to 200,000 characters. Open the saved JSON file locally for the full report.")}</div>}
    <pre className="raw-json" tabIndex={0}>{clipped ? `${serialized.slice(0, 200_000)}\n… preview truncated …` : serialized}</pre>
  </section>;
}

function AboutView({ report }: { report: Report }) {
  const config = report.scan_config;
  return <>
    <section className="section-block"><SectionHead title="Scan record" detail="Settings and timestamps let you understand what this report actually covers." />
      <DefinitionList items={[{ label: 'Tool', value: `${report.tool} ${report.tool_version}` }, { label: 'Schema', value: report.schema_version }, { label: 'Started', value: displayTime(report.started_at) }, { label: 'Completed', value: displayTime(report.completed_at) }, { label: 'Duration', value: duration(report.started_at, report.completed_at) }, { label: 'Target scope', value: report.target_scope }, { label: 'Primary exchange', value: readable(report.primary_request_id) }, { label: 'Request count', value: report.requests.length }, { label: 'Redirect count', value: report.redirects.length }]} />
    </section>
    <section className="section-block"><SectionHead title="Effective options" detail="Secrets, CA paths and request bodies are not stored in this document." />
      <DefinitionList items={[{ label: 'Private targets', value: t(config.allow_private ? 'Explicitly allowed' : 'Blocked by default') }, { label: 'Same host', value: t(config.same_host ? 'Enabled' : 'Disabled') }, { label: 'Redirect trace', value: t(config.trace_enabled ? 'Enabled' : 'Disabled') }, { label: 'CORS probe', value: t(config.cors_probe_enabled ? 'Enabled' : 'Disabled') }, { label: 'Max redirects', value: config.max_redirects }, { label: 'Request budget', value: config.max_requests || t('Not declared') }, { label: 'Timeout', value: `${config.timeout_millis} ms` }, { label: 'Connect timeout', value: `${config.connect_timeout_millis} ms` }, { label: 'Max response', value: `${config.max_response_bytes} bytes` }, { label: 'Explicit CA bundle', value: t(config.trust_bundle_provided ? 'Provided' : 'Not provided') }]} />
    </section>
    <section className="section-block"><SectionHead title="Coverage and limitations" detail="An empty finding set cannot establish that the application is secure." />
      <DefinitionList items={[{ label: 'Evidence truncated', value: t(report.truncated ? 'Yes' : 'No') }, { label: 'Omitted inputs', value: report.omitted_inputs }, { label: 'Omitted findings', value: report.omitted_findings }, { label: 'Omitted evidence', value: report.omitted_evidence }]} />
      <TextList values={[...report.limitations, ...report.score.limitations].map(reportLimitation)} empty="No further limitations recorded." />
    </section>
  </>;
}
