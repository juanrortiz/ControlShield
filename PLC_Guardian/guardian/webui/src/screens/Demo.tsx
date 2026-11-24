import { useEffect, useRef, useState } from 'react';
import {
  RiArrowLeftSLine, RiArrowRightSLine, RiInformationFill, RiLockLine, RiPlayFill, RiShutDownLine, RiRestartLine,
  RiStopFill,
} from '@remixicon/react';
import * as Alert from '@/components/ui/alert';
import * as Button from '@/components/ui/button';
import * as SegmentedControl from '@/components/ui/segmented-control';
import * as StatusBadge from '@/components/ui/status-badge';
import * as Switch from '@/components/ui/switch';
import * as Tooltip from '@/components/ui/tooltip';
import { cn } from '@/utils/cn';
import { api } from '@/api';
import { useGuardian } from '@/store';
import { Topology } from '@/components/Topology';
import { Card, FeedPanel } from '@/ui';

const ACTOR_RING: Record<string, string> = { hmi: 'text-information-base', laptop: 'text-teal-500', attacker: 'text-error-base' };
const COILS: [number, string, string][] = [
  [2, '%M2', 'Start'], [3, '%M3', 'Stop'], [4, '%M4', 'Maintenance bypass'], [5, '%M5', 'Reset'], [6, '%M6', 'Overload'], [7, '%M7', 'Guardian lockout'],
];
const COIL_ON: Record<number, string> = { 2: 'bg-success-base', 3: 'bg-success-base', 4: 'bg-error-base', 5: 'bg-success-base', 6: 'bg-error-base', 7: 'bg-purple-500' };

function Tip({ tip, children }: { tip: string; children: React.ReactNode }) {
  return (
    <Tooltip.Root>
      <Tooltip.Trigger asChild><span className='inline-flex'>{children}</span></Tooltip.Trigger>
      <Tooltip.Content size='small' className='max-w-[280px]'>{tip}</Tooltip.Content>
    </Tooltip.Root>
  );
}

function TankPanel() {
  const { state } = useGuardian();
  const plc = state?.plc ?? null;
  const prev = useRef<number | null>(null);
  const [rising, setRising] = useState(false);
  useEffect(() => {
    if (!plc) { prev.current = null; setRising(false); return; }
    setRising(prev.current !== null && plc.level > prev.current);
    prev.current = plc.level;
  }, [plc?.level, plc]);
  const level = plc?.level ?? 0;
  const fill = level > 100 ? 'bg-error-base' : level > 80 ? 'bg-warning-base' : 'bg-information-base';
  const locked = !!plc?.coils[7];
  let status = ['PLC offline', 'text-text-soft-400'];
  if (plc) {
    if (locked && !rising) status = ['LOCKED OUT by Guardian', 'text-purple-500'];
    else if (level > 100) status = [rising ? 'OVERFLOW, still rising' : 'OVERFLOW (level held)', 'text-error-base'];
    else if (rising) status = ['Filling…', 'text-information-base'];
    else if (level >= 80) status = ['Stopped at the level-80 limit', 'text-success-base'];
    else status = [level === 0 ? 'Idle / empty' : 'Idle', 'text-text-sub-600'];
  }
  const pct = (v: number) => `${Math.min(100, (v / 150) * 100)}%`;
  return (
    <Card title='PLC process (simulated)' className='flex flex-col'>
      <div className='flex gap-4'>
        <div className='relative h-48 w-16 shrink-0 overflow-hidden rounded-xl bg-bg-weak-50 ring-1 ring-inset ring-stroke-soft-200'>
          <div className={cn('absolute bottom-0 w-full transition-all duration-300', fill)} style={{ height: pct(level) }} />
          <div className='absolute w-full border-t border-dashed border-success-base' style={{ bottom: pct(80) }} />
          <div className='absolute w-full border-t border-dashed border-error-base' style={{ bottom: pct(100) }} />
          <span className='absolute left-1 text-[10px] text-success-base' style={{ bottom: `calc(${pct(80)} + 2px)` }}>80</span>
          <span className='absolute left-1 text-[10px] text-error-base' style={{ bottom: `calc(${pct(100)} + 2px)` }}>100</span>
        </div>
        <div className='flex-1'>
          <div className='mb-1 text-label-md text-text-strong-950'>level {plc ? level : '–'}</div>
          <ul className='space-y-1'>
            {COILS.map(([addr, a, name]) => (
              <li key={addr} className='flex items-center gap-2 text-paragraph-sm text-text-sub-600'>
                <span className={cn('size-2.5 rounded-full', plc?.coils[addr] ? COIL_ON[addr] : 'bg-bg-soft-200')} />
                <span className='font-mono text-text-strong-950'>{a}</span> {name}
              </li>
            ))}
          </ul>
        </div>
      </div>
      <div className={cn('mt-3 flex items-center gap-1.5 text-label-sm', status[1])}>{locked && <RiLockLine className='size-4' />}{status[0]}</div>
      <p className='mt-2 text-paragraph-xs text-text-soft-400'>Illustrative simulation: fill rate and the lockout's effect are not measurements of the real PLC.</p>
    </Card>
  );
}

function Tour() {
  const { meta, state } = useGuardian();
  const [i, setI] = useState(0);
  if (!meta) return null;
  const step = meta.tour[i];
  const run = async (n: number) => {
    const r = await api.post<{ goto?: string }>('/api/tour/run', { step: n });
    if (r?.goto) window.dispatchEvent(new CustomEvent('guardian:goto', { detail: r.goto }));
  };
  return (
    <Card className='bg-bg-weak-50'>
      <div className='flex flex-wrap items-center justify-between gap-4'>
        <div className='min-w-[260px] flex-1'>
          <div className='mb-1 flex items-center gap-2'>
            <span className='rounded-md bg-primary-alpha-10 px-1.5 py-0.5 text-label-xs text-primary-base'>Guided tour · {i + 1}/{meta.tour.length}</span>
            <h2 className='text-label-md text-text-strong-950'>{step.title}</h2>
          </div>
          <p className='text-paragraph-sm text-text-sub-600'>{step.text}</p>
          <div className='mt-2 flex gap-1'>
            {meta.tour.map((_, n) => (
              <button key={n} onClick={() => setI(n)} aria-label={`Step ${n + 1}`}
                className={cn('h-1.5 rounded-full transition-all', n === i ? 'w-6 bg-primary-base' : 'w-3 bg-bg-soft-200 hover:bg-bg-sub-300')} />
            ))}
          </div>
        </div>
        <div className='flex gap-2'>
          <Button.Root variant='neutral' mode='stroke' size='small' onClick={() => setI((i + meta.tour.length - 1) % meta.tour.length)} aria-label='Previous step'>
            <Button.Icon as={RiArrowLeftSLine} />
          </Button.Root>
          <Button.Root size='small' onClick={() => run(i)} disabled={i !== 0 && state?.system !== 'running'}>
            <Button.Icon as={RiPlayFill} /> Run this step
          </Button.Root>
          <Button.Root variant='neutral' mode='stroke' size='small' onClick={() => setI((i + 1) % meta.tour.length)} aria-label='Next step'>
            <Button.Icon as={RiArrowRightSLine} />
          </Button.Root>
        </div>
      </div>
    </Card>
  );
}

function Seg({ value, onChange, items }: { value: string; onChange: (v: string) => void; items: [string, string, string][] }) {
  return (
    <SegmentedControl.Root value={value} onValueChange={onChange}>
      <SegmentedControl.List className='w-fit'>
        {items.map(([v, label, tip]) => (
          <Tip key={v} tip={tip}>
            <SegmentedControl.Trigger value={v} className='px-3'>{label}</SegmentedControl.Trigger>
          </Tip>
        ))}
      </SegmentedControl.List>
    </SegmentedControl.Root>
  );
}

function Sw({ label, tip, checked, onChange }: { label: string; tip: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <Tip tip={tip}>
      <label className='flex cursor-pointer items-center gap-2 text-label-sm text-text-strong-950'>
        <Switch.Root checked={checked} onCheckedChange={onChange} /> {label}
      </label>
    </Tip>
  );
}

export default function Demo() {
  const { state, meta, rows, anims, console: con } = useGuardian();
  if (!state || !meta) return <div className='p-8 text-text-sub-600'>Connecting to the PLC Guardian server…</div>;
  const running = state.system === 'running';
  const busy = state.system === 'starting' || state.system === 'stopping';
  const sysStatus = { stopped: ['disabled', 'Stopped'], starting: ['pending', 'Starting…'], running: ['completed', 'Running'], stopping: ['pending', 'Stopping…'] }[state.system] as ['disabled' | 'pending' | 'completed', string];
  const ctl = (b: Record<string, unknown>) => api.post('/api/control', b);

  const counters: [keyof typeof state.counts, string, string][] = [
    ['allow', 'Allowed', 'text-success-base'], ['alert', 'Alerts', 'text-warning-base'], ['detect', 'Detected only', 'text-orange-500'],
    ['block', 'Blocked', 'text-error-base'], ['lock', 'Lockouts', 'text-purple-500'],
  ];

  return (
    <Tooltip.Provider delayDuration={150}>
      <div className='flex flex-col gap-3'>
        <Tour />

        <Card>
          <div className='flex flex-wrap items-end gap-x-6 gap-y-3'>
            <div className='flex items-center gap-2'>
              <Button.Root size='small' disabled={state.system !== 'stopped'} onClick={() => api.post('/api/system/start')}>
                <Button.Icon as={RiShutDownLine} /> Start system
              </Button.Root>
              <Button.Root variant='neutral' mode='stroke' size='small' disabled={!(running || state.system === 'starting')} onClick={() => api.post('/api/system/stop')}>
                <Button.Icon as={RiStopFill} /> Stop
              </Button.Root>
              <StatusBadge.Root status={sysStatus[0]} variant='light'><StatusBadge.Dot />{sysStatus[1]}</StatusBadge.Root>
            </div>
            <div>
              <div className='mb-1 text-paragraph-xs text-text-sub-600'>Is Guardian in the path?</div>
              <Seg value={state.route} onChange={(v) => ctl({ route: v })} items={[
                ['on', 'Guardian ON', "Clients talk to the PLC THROUGH Guardian (Guardian's blocking proxy, demo only)."],
                ['off', 'Guardian OFF', "Clients talk straight to the PLC: no checks, no log. This is the 'before' picture."]]} />
            </div>
            <div>
              <div className='mb-1 text-paragraph-xs text-text-sub-600'>Enforcement mode</div>
              <Seg value={state.mode} onChange={(v) => ctl({ mode: v })} items={[
                ['monitor', 'Monitor', 'Guardian detects + logs an attack but still forwards it to the PLC (Iteration 1).'],
                ['block', 'Block', 'Guardian refuses unauthorized requests: the PLC never sees them (Iteration 2).']]} />
            </div>
            <div className='flex flex-col gap-1.5'>
              <Sw label='Auto-lockout (D-007)' checked={state.lockout} onChange={(v) => ctl({ lockout: v })}
                tip='D-007: when Guardian sees a BLOCK-grade event it writes the lockout coil %M7 on the PLC itself.' />
              <Sw label='Allowlist attacker (read-only)' checked={state.allow_attacker} onChange={(v) => ctl({ allow_attacker: v })}
                tip='Adds 127.0.0.99 to the allowlist as READ-ONLY (live config reload). Its writes are still refused.' />
            </div>
            <div className='ml-auto'>
              <Tip tip='Presenter reset: writes zeros straight to the simulated PLC, bypassing Guardian. Not an attack.'>
                <Button.Root variant='neutral' mode='ghost' size='small' disabled={!running} onClick={() => api.post('/api/reset')}>
                  <Button.Icon as={RiRestartLine} /> Reset PLC
                </Button.Root>
              </Tip>
            </div>
          </div>
        </Card>

        <div className='grid gap-3 xl:grid-cols-[1fr_340px]'>
          <Card title='Traffic path' className='min-h-[300px]'>
            <div className='h-[270px]'><Topology state={state} anims={anims} /></div>
          </Card>
          <TankPanel />
        </div>

        <Alert.Root variant='lighter' status='information' size='large'>
          <Alert.Icon as={RiInformationFill} />
          <span className='font-medium'>{state.result}</span>
        </Alert.Root>

        <div className='grid gap-3 lg:grid-cols-3'>
          {meta.actors.map((a) => (
            <Card key={a.key} title={<span className={cn('font-medium', ACTOR_RING[a.key])}>{a.label} <span className='font-mono text-paragraph-xs text-text-sub-600'>{a.ip}</span></span>}>
              <div className='grid grid-cols-2 gap-2'>
                {meta.scenarios[a.key].map((s) => (
                  <Tip key={s.id} tip={s.tip}>
                    <Button.Root variant='neutral' mode='stroke' size='xsmall' className='w-full justify-center' disabled={!running}
                      onClick={() => api.post('/api/scenario', { id: s.id })}>
                      {s.label}
                    </Button.Root>
                  </Tip>
                ))}
              </div>
            </Card>
          ))}
        </div>

        <div className='flex flex-wrap items-center gap-2'>
          {counters.map(([k, label, color]) => (
            <div key={k} className='flex items-baseline gap-2 rounded-xl bg-bg-white-0 px-3 py-2 ring-1 ring-inset ring-stroke-soft-200'>
              <span className={cn('text-title-h5', color)}>{state.counts[k]}</span>
              <span className='text-paragraph-sm text-text-sub-600'>{label}</span>
            </div>
          ))}
          <Button.Root variant='neutral' mode='ghost' size='xsmall' className='ml-auto' onClick={() => api.post('/api/clear', { ch: 'demo' })}>Clear view</Button.Root>
        </div>

        <FeedPanel rows={rows.demo} lines={con.demo} empty='Start the system, then use the buttons above.' />
      </div>
    </Tooltip.Provider>
  );
}
