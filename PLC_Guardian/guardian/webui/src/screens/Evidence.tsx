import { useCallback, useEffect, useRef, useState } from 'react';
import { RiCheckboxCircleFill, RiCloseCircleFill, RiDownload2Line, RiListCheck2, RiShieldCheckLine, RiSpyLine } from '@remixicon/react';
import * as Alert from '@/components/ui/alert';
import * as Button from '@/components/ui/button';
import * as Input from '@/components/ui/input';
import * as Select from '@/components/ui/select';
import { api, type Row } from '@/api';
import { useGuardian } from '@/store';
import { Card, FeedTable, PageTitle } from '@/ui';

type LogInfo = { path: string; name: string; mtime: number; size: number };
type Verify = { ok: boolean; records: number; bad_seq: number | null; message: string };
type Tamper = { original_ok: boolean; original_message: string; record_no: number; was_block: boolean; copy_ok: boolean; copy_message: string };
type Banner = { kind: 'verify'; r: Verify } | { kind: 'tamper'; r: Tamper } | null;

const sleep = (ms: number) => new Promise((res) => setTimeout(res, ms));

export default function Evidence({ auto = false, onAutoDone }: { auto?: boolean; onAutoDone?: () => void }) {
  const { state } = useGuardian();
  const [logs, setLogs] = useState<LogInfo[]>([]);
  const [path, setPath] = useState('');
  const [rows, setRows] = useState<Row[]>([]);
  const [banner, setBanner] = useState<Banner>(null);
  const [busy, setBusy] = useState(false);
  const autoRan = useRef(false);

  const refresh = useCallback(async () => {
    const l = await api.get<LogInfo[]>('/api/evidence/logs', true);
    if (l) setLogs(l);
    return l ?? [];
  }, []);

  const load = useCallback(async (p: string) => {
    const r = await api.get<Row[]>(`/api/evidence/records?path=${encodeURIComponent(p)}`);
    if (r) setRows(r);
  }, []);

  const verify = useCallback(async (p: string) => {
    const r = await api.post<Verify>('/api/evidence/verify', { path: p });
    if (r) { setBanner({ kind: 'verify', r }); await load(p); }
    await refresh();
    return r;
  }, [load, refresh]);

  const tamper = useCallback(async (p: string) => {
    const r = await api.post<Tamper>('/api/evidence/tamper', { path: p });
    if (r) setBanner({ kind: 'tamper', r });
    await refresh();
    return r;
  }, [refresh]);

  // re-fetch the list on mount; default the picker to the demo log (or the newest log)
  useEffect(() => {
    refresh().then((l) => setPath((cur) => cur || state?.demo_log || l[0]?.path || ''));
  }, [refresh, state?.demo_log]);

  // tour step 7: pick the demo log, verify, load, then tamper with a copy
  useEffect(() => {
    if (!auto || autoRan.current) return;
    autoRan.current = true;
    (async () => {
      const l = await refresh();
      const p = state?.demo_log || l[0]?.path || '';
      if (!p) { onAutoDone?.(); return; }
      setPath(p);
      setBusy(true);
      await verify(p);
      await sleep(1800);
      await tamper(p);
      setBusy(false);
      onAutoDone?.();
    })();
  }, [auto, refresh, verify, tamper, state?.demo_log, onAutoDone]);

  const act = (fn: (p: string) => Promise<unknown>) => async () => {
    if (!path) return;
    setBusy(true);
    await fn(path);
    setBusy(false);
  };

  return (
    <div className='flex flex-col gap-3'>
      <PageTitle title='Evidence' sub='Verify a hash-chained evidence log, export it, or prove that tampering is detected.' />

      <Card title='Evidence log'>
        <div className='flex flex-wrap items-center gap-3'>
          <div className='min-w-[320px] flex-1'>
            <Select.Root value={path} onValueChange={setPath}>
              <Select.Trigger><Select.Value placeholder={logs.length ? 'Choose a log…' : 'No logs yet: run the demo first'} /></Select.Trigger>
              <Select.Content>
                {logs.map((l) => <Select.Item key={l.path} value={l.path}>{l.name} · {(l.size / 1024).toFixed(1)} KB</Select.Item>)}
              </Select.Content>
            </Select.Root>
          </div>
          <div className='min-w-[260px] flex-1'>
            <Input.Root><Input.Wrapper><Input.Input placeholder='…or paste a path under the project / data folder' value={path} onChange={(e) => setPath(e.target.value)} /></Input.Wrapper></Input.Root>
          </div>
        </div>
        <div className='mt-3 flex flex-wrap items-center gap-2'>
          <Button.Root size='small' disabled={!path || busy} onClick={act(verify)}>
            <Button.Icon as={RiShieldCheckLine} /> Verify hash chain
          </Button.Root>
          <Button.Root variant='neutral' mode='stroke' size='small' disabled={!path || busy} onClick={act(tamper)}>
            <Button.Icon as={RiSpyLine} /> Tamper with a COPY, then verify
          </Button.Root>
          <Button.Root variant='neutral' mode='stroke' size='small' disabled={!path || busy} onClick={act(load)}>
            <Button.Icon as={RiListCheck2} /> Show records
          </Button.Root>
          <Button.Root asChild variant='neutral' mode='stroke' size='small' disabled={!path}>
            <a href={path ? `/api/evidence/export?path=${encodeURIComponent(path)}` : undefined} download aria-disabled={!path}>
              <Button.Icon as={RiDownload2Line} /> Export CSV
            </a>
          </Button.Root>
        </div>
      </Card>

      {banner?.kind === 'verify' && (
        <Alert.Root variant='lighter' status={banner.r.ok ? 'success' : 'error'} size='large'>
          <Alert.Icon as={banner.r.ok ? RiCheckboxCircleFill : RiCloseCircleFill} />
          <div>
            <div className='font-medium'>{banner.r.ok ? 'PASS' : 'FAIL'} · {banner.r.message}</div>
            <div className='text-paragraph-xs'>{banner.r.records} records checked.</div>
          </div>
        </Alert.Root>
      )}

      {banner?.kind === 'tamper' && (
        <div className='flex flex-col gap-2'>
          <Alert.Root variant='lighter' status={banner.r.original_ok ? 'success' : 'error'} size='large'>
            <Alert.Icon as={banner.r.original_ok ? RiCheckboxCircleFill : RiCloseCircleFill} />
            <div>
              <div className='font-medium'>Original log: {banner.r.original_ok ? 'PASS' : 'FAIL'}</div>
              <div className='text-paragraph-xs'>{banner.r.original_message}</div>
            </div>
          </Alert.Root>
          <Alert.Root variant='lighter' status={banner.r.copy_ok ? 'success' : 'error'} size='large'>
            <Alert.Icon as={banner.r.copy_ok ? RiCheckboxCircleFill : RiCloseCircleFill} />
            <div>
              <div className='font-medium'>
                Copy with record #{banner.r.record_no} edited{banner.r.was_block ? ' (a BLOCK rewritten as ALLOW)' : ''}: {banner.r.copy_ok ? 'PASS' : 'FAIL'}
              </div>
              <div className='text-paragraph-xs'>{banner.r.copy_message}</div>
              <div className='mt-1 text-paragraph-xs'>The original file was not touched.</div>
            </div>
          </Alert.Root>
        </div>
      )}

      <p className='text-paragraph-sm text-text-sub-600'>
        Each record stores the SHA-256 of the previous record plus its own content. Change, delete or reorder any line and every
        later hash stops matching, so tampering is evident (detectable), not impossible. Hash the log into the case notes after each run.
      </p>

      <FeedTable rows={rows} follow={false} className='h-[360px]' empty='Pick a log and press “Verify hash chain” or “Show records”.' />
    </div>
  );
}
