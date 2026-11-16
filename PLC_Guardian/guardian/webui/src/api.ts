import { toast } from 'sonner';

export type Row = {
  id: number;
  ch: string;
  time: string;
  src: string;
  what: string;
  verdict: string;
  why: string;
  tag: string;
};
export type Plc = { coils: number[]; level: number } | null;
export type Counts = Record<'allow' | 'alert' | 'detect' | 'block' | 'lock', number>;
export type AppState = {
  system: 'stopped' | 'starting' | 'running' | 'stopping';
  route: 'on' | 'off';
  mode: 'monitor' | 'block';
  lockout: boolean;
  allow_attacker: boolean;
  counts: Counts;
  plc: Plc;
  result: string;
  demo_log: string | null;
  lab_enabled: boolean;
  lab_running: Record<string, boolean>;
  lab_logs: Record<string, string>;
  analyze_busy: boolean;
};
export type Meta = {
  actors: { key: string; label: string; ip: string }[];
  scenarios: Record<string, { id: string; label: string; tip: string }[]>;
  tour: { title: string; text: string }[];
  lab_enabled: boolean;
};
export type AnalyzeResult = {
  mode: string;
  rc: number;
  kind: string;
  path: string;
  pcap: string;
  sha_before: string;
  sha_after: string;
  unchanged: boolean;
  rows: Row[];
  report: string;
  log?: string;
};

async function call<T>(method: string, path: string, body?: unknown, quiet = false): Promise<T | null> {
  try {
    const r = await fetch(path, {
      method,
      headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const data = await r.json();
    if (!r.ok) {
      if (!quiet) toast.error(data.error ?? `Request failed (${r.status})`);
      return null;
    }
    return data as T;
  } catch (e) {
    if (!quiet) toast.error(`Cannot reach the PLC Guardian server: ${(e as Error).message}`);
    return null;
  }
}

export const api = {
  get: <T,>(path: string, quiet = false) => call<T>('GET', path, undefined, quiet),
  post: <T,>(path: string, body: unknown = {}) => call<T>('POST', path, body),
};
