export interface EvidenceRef {
  exchange_id: string;
  source: string;
  code: string;
  hop_index: number;
  item_index: number;
}

export interface Finding {
  finding_id: string;
  rule_id: string;
  rule_version: string;
  category: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
  target: string;
  evidence: EvidenceRef[];
  observation: string;
  inference: string;
  hypothesis: string;
  impact: string;
  remediation: string;
  references: string[];
  limitations: string[];
}

export interface HeaderSummary {
  id: string;
  name: string;
  occurrences: number;
  applicability: string;
  status: string;
  effective: string;
  truncated: boolean;
}

export interface CookieSummary {
  position: number;
  name: string;
  parse: string;
  acceptance: string;
  secure: boolean;
  secure_status: string;
  http_only: boolean;
  http_only_status: string;
  same_site: string;
  domain: string;
  domain_host_only: boolean;
  path_scope: string;
  session_like: boolean;
  identity_repeated: boolean;
  truncated: boolean;
}

export interface CertificateSummary {
  subject: string;
  issuer: string;
  sha256: string;
  not_before: string;
  not_after: string;
  days_remaining: number;
  validity: string;
  sans: { kind: string; value: string }[];
  truncated: boolean;
}

export interface TLSSummary {
  status: string;
  version: string;
  cipher_suite: string;
  negotiated_protocol: string;
  certificates: CertificateSummary[];
  truncated: boolean;
}

export interface CSPSummary {
  capture: string;
  applicability: string;
  policies: {
    disposition: string;
    field_index: number;
    member_index: number;
    parse: string;
    directives: {
      name: string;
      kind: string;
      status: string;
      sources: { kind: string; keyword: string; scheme: string; host: string; port: string; subdomain_wildcard: boolean; redacted: boolean }[];
    }[];
    truncated: boolean;
  }[];
  observations: string[];
  truncated: boolean;
}

export interface CORSSummary {
  capture: string;
  origin_status: string;
  origin_kind: string;
  origin_value: string;
  credentials_status: string;
  credentials_enabled: boolean;
  vary_status: string;
  vary_origin: boolean;
  cache_status: string;
  cache_fresh_shared: boolean;
  observations: string[];
  truncated: boolean;
}

export interface RequestSummary {
  id: string;
  target: string;
  method: string;
  status_code: number;
  result: string;
  protocol: string;
  duration_millis: number;
  resolution: {
    host: string;
    source: string;
    policy_version: string;
    chosen: string;
    decision: { allowed: boolean; reason: string; class: string };
    addresses: { returned: string; normalized: string; decision: { allowed: boolean; reason: string; class: string } }[];
  };
  peer: { expected: string; observed: string; verified: boolean; decision: string };
  tls: TLSSummary;
  headers: HeaderSummary[];
  cookies: CookieSummary[];
  cookie_capture: string;
  cookie_field_count: number;
  cookie_analyzed_fields: number;
  cookie_omitted_fields: number;
  cookie_truncated: boolean;
  csp: CSPSummary;
  cors: CORSSummary;
}

export interface RedirectSummary {
  hop_index: number;
  response_id: string;
  target: string;
  status_code: number;
  location_status: string;
  next_target: string;
}

export interface Report {
  schema_version: string;
  tool: string;
  tool_version: string;
  started_at: string;
  completed_at: string;
  target: string;
  target_scope: 'root' | 'redacted';
  final_target: string;
  primary_request_id: string;
  scan_config: {
    allow_private: boolean;
    same_host: boolean;
    trace_enabled: boolean;
    max_redirects: number;
    max_requests: number;
    timeout_millis: number;
    connect_timeout_millis: number;
    max_response_bytes: number;
    cors_probe_enabled: boolean;
    trust_bundle_provided: boolean;
  };
  requests: RequestSummary[];
  redirects: RedirectSummary[];
  redirect_stop: string;
  cors_probe: { attempts: { id: string; kind: string; origin: string; state: string; code: string; status_code: number; target: string; cors: CORSSummary }[] } | null;
  findings: Finding[];
  score: {
    model_version: string;
    status: string;
    value: number | null;
    label: string;
    target: string;
    assessed_weight: number;
    possible_weight: number;
    coverage_percent: number;
    components: { domain: string; weight: number; status: string; penalties: { rule_id: string; points: number }[] }[];
    limitations: string[];
  };
  truncated: boolean;
  omitted_inputs: number;
  omitted_findings: number;
  omitted_evidence: number;
  skipped_inputs: number;
  limitations: string[];
}

export interface DiffResult {
  diff_version: string;
  status: 'comparable' | 'partial' | 'incomparable';
  target: string;
  before_started: string;
  after_started: string;
  changes: { kind: string; key: string; before: string; after: string }[];
  unknown: { section: string; key: string; reason: string }[];
}

export type View = 'overview' | 'findings' | 'http' | 'tls' | 'headers' | 'cookies' | 'csp' | 'cors' | 'redirects' | 'diff' | 'raw' | 'about';

export function primaryRequest(report: Report): RequestSummary | undefined {
  return report.requests.find((request) => request.id === report.primary_request_id);
}
