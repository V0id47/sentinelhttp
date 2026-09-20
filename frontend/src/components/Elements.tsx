import type { ReactNode } from 'react';
import { readable } from '../format';
import { t } from '../i18n';

export function SectionHead({ title, detail }: { title: string; detail?: string }) {
  return <div className="section-head"><h2>{t(title)}</h2>{detail && <p>{t(detail)}</p>}</div>;
}

export function Empty({ title, detail }: { title: string; detail: string }) {
  return <div className="empty-state"><strong>{t(title)}</strong><p>{t(detail)}</p></div>;
}

export function DefinitionList({ items }: { items: { label: string; value: ReactNode }[] }) {
  return <dl className="definition-list">{items.map(({ label, value }) => <div key={label}><dt>{t(label)}</dt><dd>{value}</dd></div>)}</dl>;
}

export function State({ value, tone }: { value: string; tone?: 'good' | 'warn' | 'bad' | 'muted' }) {
  return <span className={`state state-${tone ?? 'muted'}`}>{t(readable(value))}</span>;
}

export function TextList({ values, empty }: { values: string[]; empty: string }) {
  if (values.length === 0) return <p className="muted">{t(empty)}</p>;
  return <ul className="text-list">{values.map((value, index) => <li key={`${value}-${index}`}>{value}</li>)}</ul>;
}
