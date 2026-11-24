import { useCallback, useEffect, useRef, useState } from 'react';
import { RiAlertFill, RiEraserLine, RiPlayFill, RiRadarLine, RiRefreshLine, RiStopFill } from '@remixicon/react';
import * as Alert from '@/components/ui/alert';
import * as Button from '@/components/ui/button';
import * as Input from '@/components/ui/input';
import * as Modal from '@/components/ui/modal';
import * as Select from '@/components/ui/select';
import * as StatusBadge from '@/components/ui/status-badge';
import * as Switch from '@/components/ui/switch';
import { toast } from 'sonner';
import { api } from '@/api';
import { useGuardian } from '@/store';
import { Card, FeedPanel, PageTitle } from '@/ui';

type LabCfg = {
  active_response: boolean;
  http_watch: boolean;
  info: { plc: string; lockout_coil: number; hmi_watch: string; allowlist: string[] };
};

type Coils = { plc: string; own_ip: string | null; reachable: boolean; writer_ok: boolean; coils: Record<string, number> };

/** One-press clears for the real PLC, for use while demoing. */
function QuickClear() {
  const [c, setC] = useState<Coils | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const refresh = useCallback(async () => {
    const r = await api.get<Coils>('/api/lab/coils', true);
    setC(r ?? null);
  }, []);
  // Poll the real PLC only while this card is actually on screen (all screens stay mounted, so
  // check visibility) and the tab is in the foreground, at most once every 5 s.
  const box = useRef<HTMLDivElement>(null);
  const last = useRef(0);
  useEffect(() => {
    const tick = () => {
      const visible = !!box.current && box.current.offsetParent !== null && !document.hidden;
      if (visible && Date.now() - last.current >= 5000) {
        last.current = Date.now();
        refresh();
      }
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [refresh]);

  const clear = async (coil: number, name: string) => {
    setBusy(coil);
    const r = await api.post<Coils>('/api/lab/clear', { coil });
    setBusy(null);
    if (r) {
      setC(r);
      toast.success(`${name} cleared (%M${coil} = 0)`);
    }
  };
  const items = [
    { coil: 7, key: 'M7', name: 'Control Shield', sub: '%M7 · Guardian lockout', on: 'LOCKED OUT', off: 'clear' },
    { coil: 4, key: 'M4', name: 'Maintenance bypass', sub: '%M4 · defeats the level-80 stop', on: 'BYPASS ON', off: 'off' },
  ];
  return (
    <div ref={box}>
    <Card
      title='Quick clear (real PLC)'
      right={
        <span className='text-paragraph-xs text-text-sub-600'>
          {c?.reachable ? `PLC ${c.plc} · writing as ${c.own_ip}` : 'PLC unreachable'}
        </span>
      }
    >
      <div className='grid gap-3 sm:grid-cols-2'>
        {items.map((it) => {
          const on = c?.reachable ? c.coils[it.key] === 1 : null;
          return (
            <div key={it.coil} className='flex items-center justify-between gap-3 rounded-xl bg-bg-weak-50 p-3 ring-1 ring-inset ring-stroke-soft-200'>
              <div>
                <div className='text-label-sm text-text-strong-950'>{it.name}</div>
                <div className='text-paragraph-xs text-text-sub-600'>{it.sub}</div>
                <div className={on ? 'mt-1 text-label-xs text-error-base' : 'mt-1 text-label-xs text-text-sub-600'}>
                  {on === null ? 'status unknown' : on ? it.on : it.off}
                </div>
              </div>
              <Button.Root
                size='small'
                variant={on ? 'primary' : 'neutral'}
                mode={on ? 'filled' : 'stroke'}
                disabled={busy !== null || !c?.reachable || !c?.writer_ok}
                onClick={() => clear(it.coil, it.name)}
              >
                <Button.Icon as={RiEraserLine} /> {it.name}
              </Button.Root>
            </div>
          );
        })}
      </div>
      {c && c.reachable && !c.writer_ok && (
        <p className='mt-2 text-paragraph-xs text-warning-base'>
          This host ({c.own_ip}) is not an allowlisted writer in config.json, so clearing is disabled (Guardian would treat the write as an attack).
        </p>
      )}
    </Card>
    </div>
  );
}

export default function Lab() {
  const { state, rows, console: con } = useGuardian();
  const [cfg, setCfg] = useState<LabCfg | null>(null);
  const [form, setForm] = useState<{ ar: boolean; hw: boolean }>({ ar: false, hw: false });
  const [iface, setIface] = useState('');
  const [ifaces, setIfaces] = useState<string[]>([]);
  const [confirm, setConfirm] = useState<null | { title: string; text: string; go: () => void }>(null);

  const load = useCallback(async () => {
    const c = await api.get<LabCfg>('/api/lab/config', true);
    if (c) {
      setCfg(c);
      setForm({ ar: c.active_response, hw: c.http_watch });
    }
  }, []);
  useEffect(() => {
    if (state?.lab_enabled) load();
  }, [state?.lab_enabled, load]);

  if (!state) return null;
  if (!state.lab_enabled)
    return (
      <>
        <PageTitle title='Lab Mode' sub='Run the passive monitor against the lab network.' />
        <Alert.Root variant='lighter' status='warning' size='large'>
          <Alert.Icon as={RiAlertFill} />
          Lab Mode is disabled in this environment (for example inside Docker): it needs raw packet capture and access to the isolated lab network. Run <code className='font-mono'>python gui.py</code> directly on the lab host to use it.
        </Alert.Root>
      </>
    );

  const on = !!state.lab_running.monitor;
  const dirty = cfg && (form.ar !== cfg.active_response || form.hw !== cfg.http_watch);
  const apply = () =>
    setConfirm({
      title: 'Edit the real config.json?',
      text: `active_response.enabled → ${form.ar}, http_watch.enabled → ${form.hw}. The passive monitor reads both flags when it starts, so restart it for them to take effect.`,
      go: async () => {
        const c = await api.post<LabCfg>('/api/lab/apply', { active_response: form.ar, http_watch: form.hw });
        if (c) {
          setCfg(c);
          toast.success('config.json updated');
        }
      },
    });
  const toggle = () => {
    if (on) {
      void api.post('/api/lab/stop', { key: 'monitor' });
      return;
    }
    const start = () => api.post('/api/lab/start', { key: 'monitor', iface });
    if (cfg?.active_response || cfg?.http_watch) {
      setConfirm({
        title: 'Armed: this can write to the real PLC',
        text: 'active_response / http_watch is enabled in config.json. An unauthorized event will make Guardian WRITE coil %M7 on the real PLC. Continue?',
        go: start,
      });
      return;
    }
    start();
  };
  const detect = async () => {
    const l = await api.get<string[]>('/api/lab/ifaces');
    if (l) {
      setIfaces(l);
      toast.success(`${l.length} interfaces found`);
    }
  };

  return (
    <div className='flex flex-col gap-3'>
      <PageTitle title='Lab Mode' sub='Passive monitor on the lab mirror port, with the D-007 lockout and D-009 HTTP-watch flags.' />
      <Alert.Root variant='lighter' status='warning' size='large'>
        <Alert.Icon as={RiAlertFill} />
        Lab Mode runs the REAL passive monitor. “Apply” edits guardian/config.json, and an armed active-response / http_watch can write coil %M7 on the real PLC. On real hardware Guardian is passive: it detects, logs and reacts, but does not block traffic in real time. Use it only on the lab network; the Live Demo is the safe one for a presentation.
      </Alert.Root>

      <Card
        title='Live flags in guardian/config.json'
        right={
          <div className='flex gap-2'>
            <Button.Root variant='neutral' mode='ghost' size='xsmall' onClick={load}><Button.Icon as={RiRefreshLine} /> Reload</Button.Root>
            <Button.Root size='xsmall' disabled={!dirty} onClick={apply}>Apply to config.json</Button.Root>
          </div>
        }
      >
        <div className='flex flex-wrap items-center gap-x-8 gap-y-3'>
          <label className='flex cursor-pointer items-center gap-2 text-label-sm'>
            <Switch.Root checked={form.ar} onCheckedChange={(v) => setForm({ ...form, ar: v })} /> active_response.enabled{' '}
            <span className='text-text-sub-600'>(D-007 lockout; read at monitor start)</span>
          </label>
          <label className='flex cursor-pointer items-center gap-2 text-label-sm'>
            <Switch.Root checked={form.hw} onCheckedChange={(v) => setForm({ ...form, hw: v })} /> http_watch.enabled{' '}
            <span className='text-text-sub-600'>(D-009; read at monitor start)</span>
          </label>
        </div>
        {cfg && (
          <p className='mt-3 text-paragraph-xs text-text-sub-600'>
            PLC {cfg.info.plc} · lockout coil %M{cfg.info.lockout_coil} · HMI watch {cfg.info.hmi_watch}
            <br />
            Allowlist: {cfg.info.allowlist.join(', ')}
          </p>
        )}
      </Card>

      <QuickClear />

      <Card
        title='Passive monitor (mirror port)'
        right={
          <div className='flex items-center gap-2'>
            <div className='w-64'>
              <Input.Root size='small'>
                <Input.Wrapper>
                  <Input.Input placeholder='Capture interface (e.g. Ethernet)' value={iface} onChange={(e) => setIface(e.target.value)} />
                </Input.Wrapper>
              </Input.Root>
            </div>
            {ifaces.length > 0 && (
              <Select.Root size='small' value={iface} onValueChange={setIface}>
                <Select.Trigger className='w-44'><Select.Value placeholder='Detected…' /></Select.Trigger>
                <Select.Content>{ifaces.map((n) => <Select.Item key={n} value={n}>{n}</Select.Item>)}</Select.Content>
              </Select.Root>
            )}
            <Button.Root variant='neutral' mode='stroke' size='xsmall' onClick={detect}><Button.Icon as={RiRadarLine} /> Detect</Button.Root>
          </div>
        }
      >
        <div className='flex flex-wrap items-center gap-4 rounded-xl bg-bg-weak-50 p-3 ring-1 ring-inset ring-stroke-soft-200'>
          <StatusBadge.Root status={on ? 'completed' : 'disabled'} variant='light'><StatusBadge.Dot />{on ? 'Running' : 'Stopped'}</StatusBadge.Root>
          <p className="min-w-[260px] flex-1 text-paragraph-sm text-text-sub-600">
            Sniffs the switch's mirror (SPAN) port: detects and logs unauthorized traffic and, with the flags above, reacts with the D-007 lockout (%M7) and the D-009 HTTP watch. It cannot block traffic in real time. Needs Npcap and admin rights.
          </p>
          <Button.Root variant={on ? 'error' : 'primary'} mode={on ? 'stroke' : 'filled'} size='small' onClick={toggle}>
            <Button.Icon as={on ? RiStopFill : RiPlayFill} /> {on ? 'Stop' : 'Start'}
          </Button.Root>
        </div>
      </Card>

      <FeedPanel rows={rows.lab} lines={con.lab} empty='Start the passive monitor to see its evidence here.' />

      <Modal.Root open={!!confirm} onOpenChange={(o) => !o && setConfirm(null)}>
        <Modal.Content>
          <Modal.Header title={confirm?.title} description={confirm?.text} />
          <Modal.Footer>
            <Modal.Close asChild><Button.Root variant='neutral' mode='stroke' size='small' className='w-full'>Cancel</Button.Root></Modal.Close>
            <Modal.Close asChild><Button.Root size='small' className='w-full' onClick={() => confirm?.go()}>Continue</Button.Root></Modal.Close>
          </Modal.Footer>
        </Modal.Content>
      </Modal.Root>
    </div>
  );
}
