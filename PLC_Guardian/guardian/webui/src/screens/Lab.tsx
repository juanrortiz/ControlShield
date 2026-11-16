import { useCallback, useEffect, useState } from 'react';
import { RiAlertFill, RiPlayFill, RiRadarLine, RiRefreshLine, RiStopFill } from '@remixicon/react';
import * as Alert from '@/components/ui/alert';
import * as Button from '@/components/ui/button';
import * as Input from '@/components/ui/input';
import * as Modal from '@/components/ui/modal';
import * as SegmentedControl from '@/components/ui/segmented-control';
import * as Select from '@/components/ui/select';
import * as StatusBadge from '@/components/ui/status-badge';
import * as Switch from '@/components/ui/switch';
import { toast } from 'sonner';
import { api } from '@/api';
import { useGuardian } from '@/store';
import { Card, ConsolePane, FeedTable, PageTitle, Tabs } from '@/ui';

type LabCfg = {
  mode: 'monitor' | 'block';
  active_response: boolean;
  http_watch: boolean;
  info: { plc: string; lockout_coil: number; hmi_watch: string; allowlist: string[] };
};

const SENSORS: { key: string; title: string; text: string }[] = [
  { key: 'monitor', title: 'Passive monitor (mirror port)', text: 'Sniffs the SPAN/mirror port: detect + log, plus the D-007 / D-009 reactions. Needs Npcap and admin rights.' },
  { key: 'proxy', title: 'Inline Modbus proxy', text: 'Listens on TCP 502 and forwards to the PLC; blocks in block mode. Only prevents attacks if the PLC is reachable solely through this host.' },
  { key: 'httpgate', title: 'HTTP gate (HMI web API)', text: "D-008 connection-level gate in front of the HMI's port 80 (IP allowlist only)." },
];

export default function Lab() {
  const { state, rows, console: con } = useGuardian();
  const [cfg, setCfg] = useState<LabCfg | null>(null);
  const [form, setForm] = useState<{ mode: 'monitor' | 'block'; ar: boolean; hw: boolean }>({ mode: 'block', ar: false, hw: false });
  const [iface, setIface] = useState('');
  const [ifaces, setIfaces] = useState<string[]>([]);
  const [confirm, setConfirm] = useState<null | { title: string; text: string; go: () => void }>(null);

  const load = useCallback(async () => {
    const c = await api.get<LabCfg>('/api/lab/config', true);
    if (c) {
      setCfg(c);
      setForm({ mode: c.mode, ar: c.active_response, hw: c.http_watch });
    }
  }, []);
  useEffect(() => {
    if (state?.lab_enabled) load();
  }, [state?.lab_enabled, load]);

  if (!state) return null;
  if (!state.lab_enabled)
    return (
      <>
        <PageTitle title='Lab Mode' sub='Drive the real sensors against the lab network.' />
        <Alert.Root variant='lighter' status='warning' size='large'>
          <Alert.Icon as={RiAlertFill} />
          Lab Mode is disabled in this environment (for example inside Docker): it needs raw packet capture and access to the isolated lab network. Run <code className='font-mono'>python gui.py</code> directly on the lab host to use it.
        </Alert.Root>
      </>
    );

  const dirty = cfg && (form.mode !== cfg.mode || form.ar !== cfg.active_response || form.hw !== cfg.http_watch);
  const apply = () =>
    setConfirm({
      title: 'Edit the real config.json?',
      text: `enforcement.mode → ${form.mode}, active_response.enabled → ${form.ar}, http_watch.enabled → ${form.hw}. A running proxy/httpgate hot-reloads the mode; the passive monitor must be restarted for the other two.`,
      go: async () => {
        const c = await api.post<LabCfg>('/api/lab/apply', { mode: form.mode, active_response: form.ar, http_watch: form.hw });
        if (c) {
          setCfg(c);
          toast.success('config.json updated');
        }
      },
    });
  const toggle = (key: string) => {
    if (state.lab_running[key]) {
      void api.post('/api/lab/stop', { key });
      return;
    }
    const start = () => api.post('/api/lab/start', { key, iface });
    if (key === 'monitor' && (cfg?.active_response || cfg?.http_watch)) {
      setConfirm({ title: 'Armed: this can write to the real PLC', text: 'active_response / http_watch is enabled in config.json. An unauthorized event will make Guardian WRITE coil %M7 on the real PLC. Continue?', go: start });
      return;
    }
    if (key === 'proxy' && cfg?.mode === 'block') {
      setConfirm({ title: 'Start the inline proxy in block mode?', text: 'Binds TCP 502 on this host (needs a firewall rule) and BLOCKS unauthorized requests.', go: start });
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
      <PageTitle title='Lab Mode' sub='Real sensors against the isolated lab network, with the live config.json flags.' />
      <Alert.Root variant='lighter' status='warning' size='large'>
        <Alert.Icon as={RiAlertFill} />
        Lab Mode drives the REAL Guardian commands. “Apply” edits guardian/config.json, and an armed active-response / http_watch can write coil %M7 on the real PLC. Use it only on the lab network; the Live Demo is the safe one for a presentation.
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
          <div>
            <div className='mb-1 text-paragraph-xs text-text-sub-600'>Enforcement mode (proxy / httpgate, hot-reloaded)</div>
            <SegmentedControl.Root value={form.mode} onValueChange={(v) => setForm({ ...form, mode: v as 'monitor' | 'block' })}>
              <SegmentedControl.List className='w-fit'>
                <SegmentedControl.Trigger value='monitor' className='px-3'>monitor</SegmentedControl.Trigger>
                <SegmentedControl.Trigger value='block' className='px-3'>block</SegmentedControl.Trigger>
              </SegmentedControl.List>
            </SegmentedControl.Root>
          </div>
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

      <Card
        title='Run the real sensors'
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
        <div className='grid gap-3 lg:grid-cols-3'>
          {SENSORS.map((s) => {
            const on = !!state.lab_running[s.key];
            return (
              <div key={s.key} className='flex flex-col gap-3 rounded-xl bg-bg-weak-50 p-3 ring-1 ring-inset ring-stroke-soft-200'>
                <div className='flex items-center justify-between gap-2'>
                  <span className='text-label-sm text-text-strong-950'>{s.title}</span>
                  <StatusBadge.Root status={on ? 'completed' : 'disabled'} variant='light'><StatusBadge.Dot />{on ? 'Running' : 'Stopped'}</StatusBadge.Root>
                </div>
                <p className='flex-1 text-paragraph-sm text-text-sub-600'>{s.text}</p>
                <Button.Root variant={on ? 'error' : 'primary'} mode={on ? 'stroke' : 'filled'} size='small' onClick={() => toggle(s.key)}>
                  <Button.Icon as={on ? RiStopFill : RiPlayFill} /> {on ? 'Stop' : 'Start'}
                </Button.Root>
              </div>
            );
          })}
        </div>
      </Card>

      <Tabs
        className='min-h-[320px]'
        tabs={[
          { value: 'feed', label: 'Live evidence feed', content: <FeedTable rows={rows.lab} className='h-[300px]' empty='Start a sensor to see its evidence here.' /> },
          { value: 'console', label: 'Process console', content: <ConsolePane lines={con.lab} className='h-[300px]' /> },
        ]}
      />

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
