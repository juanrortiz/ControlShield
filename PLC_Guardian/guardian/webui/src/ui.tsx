import { useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { RiArrowDownLine, RiFullscreenExitLine, RiFullscreenLine } from '@remixicon/react';
import * as Badge from '@/components/ui/badge';
import * as Button from '@/components/ui/button';
import * as SegmentedControl from '@/components/ui/segmented-control';
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

// ───────────────────────────────────────────────────────── text size (persisted)
export type FeedSize = 'sm' | 'md' | 'lg';
const SIZE_KEY = 'guardian.feedSize';
const SIZES: Record<FeedSize, { text: string; head: string; cell: string; badge: string; mono: string }> = {
  sm: { text: 'text-paragraph-sm', head: 'text-label-xs', cell: 'px-3 py-1.5', badge: '', mono: 'text-paragraph-xs' },
  md: { text: 'text-paragraph-md', head: 'text-label-sm', cell: 'px-4 py-2.5', badge: '!h-7 !px-3 !text-label-sm', mono: 'text-paragraph-sm' },
  lg: { text: 'text-paragraph-lg', head: 'text-label-md', cell: 'px-5 py-3.5', badge: '!h-8 !px-3.5 !text-label-md', mono: 'text-paragraph-md' },
};

function loadSize(): FeedSize {
  try {
    const v = localStorage.getItem(SIZE_KEY);
    if (v === 'sm' || v === 'md' || v === 'lg') return v;
  } catch { /* storage unavailable: fall through */ }
  return 'md';
}
function saveSize(s: FeedSize) {
  try { localStorage.setItem(SIZE_KEY, s); } catch { /* ignore */ }
}

export function VerdictBadge({ tag, children, className }: { tag: string; children: ReactNode; className?: string }) {
  return (
    <Badge.Root variant='light' color={TAG_COLOR[tag] ?? 'gray'} size='medium' className={cn('whitespace-nowrap', className)}>
      {children}
    </Badge.Root>
  );
}

// ───────────────────────────────────────────────────────── stick-to-bottom
/**
 * Keeps a scroll container pinned to its bottom while the user is within ~40px of it.
 * `dep` must change whenever content is added (use last id + length: the row list is capped, so
 * its length alone stops changing once the cap is hit). Scrolling up pauses following.
 */
function useStickToBottom<T extends HTMLElement>(dep: unknown, enabled = true) {
  const ref = useRef<T>(null);
  const stick = useRef(true);
  const [atBottom, setAtBottom] = useState(true);

  const onScroll = useCallback(() => {
    const el = ref.current;
    if (!el) return;
    const near = el.scrollHeight - el.clientHeight - el.scrollTop <= 40;
    stick.current = near;
    setAtBottom((p) => (p === near ? p : near));
  }, []);

  useLayoutEffect(() => {
    const el = ref.current;
    if (!enabled || !el || !stick.current) return;
    el.scrollTop = el.scrollHeight;
    // a burst can add more content before paint: settle once more on the next frame
    const id = requestAnimationFrame(() => {
      if (stick.current && ref.current) ref.current.scrollTop = ref.current.scrollHeight;
    });
    return () => cancelAnimationFrame(id);
  }, [dep, enabled]);

  const jump = useCallback(() => {
    const el = ref.current;
    if (!el) return;
    stick.current = true;
    setAtBottom(true);
    el.scrollTop = el.scrollHeight;
  }, []);

  return { ref, onScroll, atBottom, jump };
}

function JumpButton({ show, onClick }: { show: boolean; onClick: () => void }) {
  if (!show) return null;
  return (
    <Button.Root size='xsmall' className='absolute bottom-3 right-5 shadow-regular-md' onClick={onClick}>
      <Button.Icon as={RiArrowDownLine} /> Jump to latest
    </Button.Root>
  );
}

/** Evidence rows as a colour-coded table that follows new rows. */
export function FeedTable({
  rows, empty = 'No events yet.', follow = true, className, wrapperClassName, size,
}: { rows: Row[]; empty?: string; follow?: boolean; className?: string; wrapperClassName?: string; size?: FeedSize }) {
  const sz = SIZES[size ?? loadSize()];
  const last = rows.length ? rows[rows.length - 1].id : 0;
  const { ref, onScroll, atBottom, jump } = useStickToBottom<HTMLDivElement>(`${rows.length}:${last}`, follow);
  const th = cn('sticky top-0 z-10 bg-bg-weak-50 text-left font-medium text-text-sub-600', sz.head, sz.cell);
  return (
    <div className={cn('relative', wrapperClassName)}>
      <div ref={ref} onScroll={onScroll}
        style={{ overflowAnchor: atBottom ? 'none' : 'auto' }}
        className={cn('overflow-auto rounded-xl ring-1 ring-inset ring-stroke-soft-200', className)}>
        <table className={cn('w-full min-w-[980px] border-collapse', sz.text)}>
          <colgroup>
            <col className='w-[8.5rem]' /><col className='w-[15rem]' /><col /><col className='w-[13rem]' /><col />
          </colgroup>
          <thead>
            <tr>
              {['Time', 'Source', 'What it tried', "Guardian's verdict", 'Why'].map((h) => <th key={h} className={th}>{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr><td colSpan={5} className='px-3 py-10 text-center text-text-soft-400'>{empty}</td></tr>
            )}
            {rows.map((r) => (
              <tr key={r.id} className='border-t border-stroke-soft-200 align-top even:bg-bg-weak-50'>
                <td className={cn('whitespace-nowrap font-mono text-text-sub-600', sz.cell, sz.mono)}>{r.time}</td>
                <td className={cn('break-words font-medium', sz.cell, TAG_TEXT[r.tag])}>{r.src}</td>
                <td className={cn('break-words font-mono text-text-strong-950', sz.cell, sz.mono)}>{r.what}</td>
                <td className={sz.cell}><VerdictBadge tag={r.tag} className={sz.badge}>{r.verdict}</VerdictBadge></td>
                <td className={cn('break-words text-text-sub-600', sz.cell)}>{r.why}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <JumpButton show={follow && !atBottom && rows.length > 0} onClick={jump} />
    </div>
  );
}

export function ConsolePane({ lines, className, wrapperClassName, size }: { lines: string[]; className?: string; wrapperClassName?: string; size?: FeedSize }) {
  const sz = SIZES[size ?? loadSize()];
  const { ref, onScroll, atBottom, jump } = useStickToBottom<HTMLDivElement>(`${lines.length}:${lines[lines.length - 1] ?? ''}`);
  return (
    <div className={cn('relative', wrapperClassName)}>
      <div ref={ref} onScroll={onScroll} style={{ overflowAnchor: atBottom ? 'none' : 'auto' }}
        className={cn('overflow-auto rounded-xl bg-bg-weak-50 p-3 font-mono text-text-sub-600 ring-1 ring-inset ring-stroke-soft-200', sz.mono, className)}>
        {lines.length === 0 ? <span className='text-text-soft-400'>No output yet.</span> : lines.map((l, i) => <div key={i} className='whitespace-pre-wrap break-all py-0.5'>{l}</div>)}
      </div>
      <JumpButton show={!atBottom && lines.length > 0} onClick={jump} />
    </div>
  );
}

/**
 * Live feed + process console in one big panel: text-size control and a full-screen mode
 * (fixed overlay + the browser Fullscreen API; Esc leaves both).
 */
export function FeedPanel({ rows, lines, empty, className }: { rows: Row[]; lines: string[]; empty?: string; className?: string }) {
  const [size, setSize] = useState<FeedSize>(loadSize);
  const [full, setFull] = useState(false);

  const exit = useCallback(() => {
    setFull(false);
    if (document.fullscreenElement) document.exitFullscreen?.().catch(() => undefined);
  }, []);
  const enter = () => {
    setFull(true);
    document.documentElement.requestFullscreen?.().catch(() => undefined);
  };

  useEffect(() => {
    if (!full) return;
    const onFs = () => { if (!document.fullscreenElement) setFull(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') exit(); };
    document.addEventListener('fullscreenchange', onFs);
    window.addEventListener('keydown', onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('fullscreenchange', onFs);
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = prev;
    };
  }, [full, exit]);

  const pick = (v: string) => {
    const s = v as FeedSize;
    setSize(s);
    saveSize(s);
  };
  const body = full ? 'min-h-0 flex-1' : 'h-[60vh] min-h-[420px]';

  return (
    <div className={cn(full ? 'fixed inset-0 z-50 flex flex-col bg-bg-white-0 p-5' : 'flex flex-col', className)}>
      <TabMenu.Root defaultValue='feed' className='flex min-h-0 flex-1 flex-col'>
        <div className='flex items-center gap-3'>
          <div className='min-w-0 flex-1'>
            <TabMenu.List>
              <TabMenu.Trigger value='feed'>Live evidence feed <span className='text-paragraph-xs text-text-soft-400'>{rows.length}</span></TabMenu.Trigger>
              <TabMenu.Trigger value='console'>Process console</TabMenu.Trigger>
            </TabMenu.List>
          </div>
          <SegmentedControl.Root value={size} onValueChange={pick} aria-label='Text size'>
            <SegmentedControl.List className='w-fit'>
              <SegmentedControl.Trigger value='sm' className='px-2.5 text-paragraph-xs'>A</SegmentedControl.Trigger>
              <SegmentedControl.Trigger value='md' className='px-2.5 text-paragraph-sm'>A</SegmentedControl.Trigger>
              <SegmentedControl.Trigger value='lg' className='px-2.5 text-paragraph-md'>A</SegmentedControl.Trigger>
            </SegmentedControl.List>
          </SegmentedControl.Root>
          <Button.Root variant='neutral' mode='stroke' size='small' onClick={full ? exit : enter}>
            <Button.Icon as={full ? RiFullscreenExitLine : RiFullscreenLine} /> {full ? 'Exit full screen' : 'Full screen'}
          </Button.Root>
        </div>
        <TabMenu.Content value='feed' forceMount className={cn('mt-3 data-[state=inactive]:hidden', body)}>
          <FeedTable rows={rows} empty={empty} size={size} wrapperClassName='h-full' className='h-full' />
        </TabMenu.Content>
        <TabMenu.Content value='console' forceMount className={cn('mt-3 data-[state=inactive]:hidden', body)}>
          <ConsolePane lines={lines} size={size} wrapperClassName='h-full' className='h-full' />
        </TabMenu.Content>
      </TabMenu.Root>
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
