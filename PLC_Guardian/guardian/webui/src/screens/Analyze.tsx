import { useEffect, useState } from 'react';
import { RiCheckboxCircleFill, RiCloseCircleFill } from '@remixicon/react';
import * as Alert from '@/components/ui/alert';
import * as Button from '@/components/ui/button';
import * as Input from '@/components/ui/input';
import * as Select from '@/components/ui/select';
import { api } from '@/api';
import { useGuardian } from '@/store';
import { Card, ConsolePane, FeedTable, PageTitle, Tabs } from '@/ui';

type Cap = { path: string; name: string; size: number };

export default function Analyze() {
  const { state, console: con, analyzeResult: res } = useGuardian();
  const [caps, setCaps] = useState<Cap[]>([]);
  const [pcap, setPcap] = useState('');
  const [baseline, setBaseline] = useState('');
  const [sha, setSha] = useState('');

  useEffect(() => {
    api.get<Cap[]>('/api/captures', true).then((c) => c && setCaps(c));
  }, []);
  useEffect(() => {
    setSha('');
    if (pcap) api.get<{ sha256: string }>(`/api/analyze/hash?path=${encodeURIComponent(pcap)}`, true).then((h) => h && setSha(h.sha256));
  }, [pcap]);

  const busy = !!state?.analyze_busy;
  const run = (mode: string) => api.post('/api/analyze/run', { mode, pcap, baseline });
  const btn = (mode: string, label: string, primary = false) => (
    <Button.Root size='small' variant={primary ? 'primary' : 'neutral'} mode={primary ? 'filled' : 'stroke'} disabled={!pcap || busy} onClick={() => run(mode)}>
      {label}
    </Button.Root>
  );
  const ok = !!res && res.rc === 0 && res.unchanged;

  return (
    <div className='flex flex-col gap-3'>
      <PageTitle title='Analyze Captures' sub='Run Guardian on a .pcapng. The capture is only read: its SHA-256 is shown before and after.' />
      <Card title='1 · Pick a capture'>
        <div className='flex flex-wrap items-center gap-3'>
          <div className='min-w-[320px] flex-1'>
            <Select.Root value={pcap} onValueChange={setPcap}>
              <Select.Trigger><Select.Value placeholder={caps.length ? 'Choose a capture…' : 'No captures found'} /></Select.Trigger>
              <Select.Content>
                {caps.map((c) => <Select.Item key={c.path} value={c.path}>{c.name} · {(c.size / 1024).toFixed(0)} KB</Select.Item>)}
              </Select.Content>
            </Select.Root>
          </div>
          <div className='min-w-[260px] flex-1'>
            <Input.Root>
              <Input.Wrapper>
                <Input.Input placeholder='…or paste a path under the project / data folder' value={pcap} onChange={(e) => setPcap(e.target.value)} />
              </Input.Wrapper>
            </Input.Root>
          </div>
        </div>
        <p className='mt-2 break-all font-mono text-paragraph-xs text-text-sub-600'>{pcap ? `SHA-256 before: ${sha || 'computing…'}` : 'SHA-256: select a capture'}</p>
      </Card>

      <Card title='2 · Run an analysis'>
        <div className='flex flex-wrap items-center gap-3'>
          {btn('analyze', 'Analyze → evidence log')}
          {btn('forensics', 'Forensics report', true)}
          {btn('baseline', 'Learn baseline')}
          <div className='ml-auto w-72'>
            <Input.Root size='small'>
              <Input.Wrapper>
                <Input.Input placeholder='Optional baseline.json path' value={baseline} onChange={(e) => setBaseline(e.target.value)} />
              </Input.Wrapper>
            </Input.Root>
          </div>
        </div>
        {busy && <p className='mt-3 text-paragraph-sm text-warning-base'>Running…</p>}
      </Card>

      {res && !busy && (
        <Alert.Root variant='lighter' status={ok ? 'success' : 'error'} size='large'>
          <Alert.Icon as={ok ? RiCheckboxCircleFill : RiCloseCircleFill} />
          <div className='min-w-0'>
            <div className='font-medium'>
              {res.mode} {res.rc === 0 ? 'finished' : `failed (exit ${res.rc})`} · capture {res.unchanged ? 'unchanged ✔' : 'CHANGED ✘'}
            </div>
            <div className='break-all font-mono text-paragraph-xs'>
              before {res.sha_before}
              <br />
              after&nbsp; {res.sha_after}
            </div>
            <div className='break-all text-paragraph-xs'>→ {res.path}</div>
          </div>
        </Alert.Root>
      )}

      <Tabs
        className='min-h-[380px]'
        tabs={[
          { value: 'findings', label: 'Findings', content: <FeedTable rows={res?.rows ?? []} follow={false} className='h-[340px]' empty='Run an analysis to see Guardian’s findings.' /> },
          {
            value: 'report',
            label: 'Forensics report',
            content: (
              <pre className='h-[340px] overflow-auto whitespace-pre-wrap rounded-xl bg-bg-weak-50 p-4 font-mono text-paragraph-xs text-text-sub-600 ring-1 ring-inset ring-stroke-soft-200'>
                {res?.report || 'Run “Forensics report” to generate one.'}
              </pre>
            ),
          },
          { value: 'console', label: 'Console', content: <ConsolePane lines={con.analyze} className='h-[340px]' /> },
        ]}
      />
    </div>
  );
}
