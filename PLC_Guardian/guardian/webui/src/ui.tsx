import { useEffect, useRef, type ReactNode } from 'react';
import * as Badge from '@/components/ui/badge';
import * as TabMenu from '@/components/ui/tab-menu-horizontal';
import { cn } from '@/utils/cn';
import type { Row } from './api';

type BadgeColor = 'gray' | 'blue' | 'orange' | 'red' | 'green' | 'yellow' | 'purple' | 'sky' | 'pink' | 'teal';

export const TAG_COLOR: Record<string, BadgeColor> = {
  allow: 'green', alert: 'yellow', detect: 'orange', block: 'red', lock: 'purple', info: 'gray', resp: 'sky', bypass: 'pink',
};
export const TAG_TEXT: Record<string, string> = {
  allow: 'text-success-base', alert: 'text-warning-base', detect: 'text-orange-500', block: 'text-error-base',
  lock: 'text-purple-500', info: 'text-text-sub-600', resp: 'text-sky-500', bypass: 'text-pink-500',
};

export function Card({ title, right, children, className }: { title?: ReactNode; right?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cn('rounded-2xl bg-bg-white-0 p-4 ring-1 ring-inset ring-stroke-soft-200', className)}>
      {(title || right) && (
        <header className='mb-3 flex items-center justify-between gap-3'>
          <h3 className='text-label-sm text-text-sub-600'>{title}</h3>
          {right}
        </header>
      )}
      {children}
    </section>
  );
}

export function PageTitle({ title, sub, right }: { title: string; sub?: string; right?: ReactNode }) {
  return (
    <div className='mb-4 flex items-start justify-between gap-4'>
      <div>
        <h1 className='text-title-h6 text-text-strong-950'>{title}</h1>
        {sub && <p className='mt-0.5 text-paragraph-sm text-text-sub-600'>{sub}</p>}
      </div>
      {right}
    </div>
  );
}

export function VerdictBadge({ tag, children }: { tag: string; children: ReactNode }) {
  return (
    <Badge.Root variant='light' color={TAG_COLOR[tag] ?? 'gray'} size='medium' className='whitespace-nowrap'>
      {children}
    </Badge.Root>
  );
}

/** Evidence rows as a colour-coded table that follows new rows. */
export function FeedTable({ rows, empty = 'No events yet.', follow = true, className }: { rows: Row[]; empty?: string; follow?: boolean; className?: string }) {
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (follow && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [rows.length, follow]);
  return (
    <div ref={box} className={cn('overflow-auto rounded-xl ring-1 ring-inset ring-stroke-soft-200', className)}>
      <table className='w-full min-w-[820px] border-collapse text-paragraph-sm'>
        <thead className='sticky top-0 z-10 bg-bg-weak-50 text-left text-label-xs text-text-sub-600'>
          <tr>
            {['Time', 'Source', 'What it tried', "Guardian's verdict", 'Why'].map((h) => (
              <th key={h} className='px-3 py-2 font-medium'>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr><td colSpan={5} className='px-3 py-6 text-center text-text-soft-400'>{empty}</td></tr>
          )}
          {rows.map((r) => (
            <tr key={r.id} className='border-t border-stroke-soft-200 align-top'>
              <td className='whitespace-nowrap px-3 py-1.5 font-mono text-text-sub-600'>{r.time}</td>
              <td className={cn('whitespace-nowrap px-3 py-1.5', TAG_TEXT[r.tag])}>{r.src}</td>
              <td className='px-3 py-1.5 font-mono text-text-strong-950'>{r.what}</td>
              <td className='px-3 py-1.5'><VerdictBadge tag={r.tag}>{r.verdict}</VerdictBadge></td>
              <td className='px-3 py-1.5 text-text-sub-600'>{r.why}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ConsolePane({ lines, className }: { lines: string[]; className?: string }) {
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [lines.length]);
  return (
    <div ref={box} className={cn('overflow-auto rounded-xl bg-bg-weak-50 p-3 font-mono text-paragraph-xs text-text-sub-600 ring-1 ring-inset ring-stroke-soft-200', className)}>
      {lines.length === 0 ? <span className='text-text-soft-400'>No output yet.</span> : lines.map((l, i) => <div key={i} className='whitespace-pre-wrap break-all'>{l}</div>)}
    </div>
  );
}

/** Tabs (AlignUI TabMenuHorizontal) with a content area per tab. */
export function Tabs({ tabs, className }: { tabs: { value: string; label: string; badge?: ReactNode; content: ReactNode }[]; className?: string }) {
  return (
    <TabMenu.Root defaultValue={tabs[0].value} className={cn('flex min-h-0 flex-col', className)}>
      <TabMenu.List>
        {tabs.map((t) => (
          <TabMenu.Trigger key={t.value} value={t.value}>
            {t.label}
            {t.badge}
          </TabMenu.Trigger>
        ))}
      </TabMenu.List>
      {tabs.map((t) => (
        <TabMenu.Content key={t.value} value={t.value} className='mt-3 min-h-0 flex-1'>
          {t.content}
        </TabMenu.Content>
      ))}
    </TabMenu.Root>
  );
}

export const mono = (s: string) => <code className='rounded bg-bg-weak-50 px-1 py-0.5 font-mono text-paragraph-xs'>{s}</code>;
