import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { api, type AnalyzeResult, type AppState, type Meta, type Row } from './api';

export type Anim = { id: number; actor: string; tag: string; blocked: boolean; direct: boolean };

type Store = {
  state: AppState | null;
  meta: Meta | null;
  rows: { demo: Row[]; lab: Row[] };
  console: { demo: string[]; lab: string[]; analyze: string[] };
  anims: Anim[];
  connected: boolean;
  analyzeResult: AnalyzeResult | null;
};

const EMPTY: Store = {
  state: null,
  meta: null,
  rows: { demo: [], lab: [] },
  console: { demo: [], lab: [], analyze: [] },
  anims: [],
  connected: false,
  analyzeResult: null,
};

const Ctx = createContext<Store>(EMPTY);
export const useGuardian = () => useContext(Ctx);

const cap = <T,>(a: T[], n = 500) => (a.length > n ? a.slice(a.length - n) : a);

export function GuardianProvider({ children }: { children: ReactNode }) {
  const [s, setS] = useState<Store>(EMPTY);
  const animId = useRef(0);

  useEffect(() => {
    api.get<Meta>('/api/meta', true).then((m) => m && setS((p) => ({ ...p, meta: m })));
    api.get<AnalyzeResult>('/api/analyze/result', true).then(
      (r) => r && r.mode && setS((p) => ({ ...p, analyzeResult: r })),
    );
    const es = new EventSource('/api/stream');
    const on = <T,>(name: string, fn: (d: T) => void) =>
      es.addEventListener(name, (e) => fn(JSON.parse((e as MessageEvent).data) as T));

    es.onopen = () => setS((p) => ({ ...p, connected: true }));
    es.onerror = () => setS((p) => ({ ...p, connected: false }));
    on<{ state: AppState; rows: Store['rows']; console: Store['console'] }>('snapshot', (d) =>
      setS((p) => ({ ...p, state: d.state, rows: d.rows, console: d.console, connected: true })),
    );
    on<AppState>('state', (d) => setS((p) => ({ ...p, state: d })));
    on<Row>('row', (r) =>
      setS((p) => {
        const ch = r.ch as 'demo' | 'lab';
        return ch in p.rows ? { ...p, rows: { ...p.rows, [ch]: cap([...p.rows[ch], r]) } } : p;
      }),
    );
    on<AppState['counts']>('counts', (c) => setS((p) => (p.state ? { ...p, state: { ...p.state, counts: c } } : p)));
    on<AppState['plc']>('plc', (plc) => setS((p) => (p.state ? { ...p, state: { ...p.state, plc } } : p)));
    on<string>('result', (t) => setS((p) => (p.state ? { ...p, state: { ...p.state, result: t } } : p)));
    on<{ ch: 'demo' | 'lab' | 'analyze'; line: string }>('console', (c) =>
      setS((p) => ({ ...p, console: { ...p.console, [c.ch]: cap([...p.console[c.ch], c.line], 400) } })),
    );
    on<{ ch: string }>('cleared', ({ ch }) =>
      setS((p) => ({
        ...p,
        rows: ch === 'demo' || ch === 'lab' ? { ...p.rows, [ch]: [] } : p.rows,
        console: ch === 'analyze' ? { ...p.console, analyze: [] } : p.console,
        state: ch === 'demo' && p.state ? { ...p.state, counts: { allow: 0, alert: 0, detect: 0, block: 0, lock: 0 } } : p.state,
      })),
    );
    on<Omit<Anim, 'id'>>('anim', (a) => {
      const id = ++animId.current;
      setS((p) => ({ ...p, anims: [...p.anims, { ...a, id }] }));
      setTimeout(() => setS((p) => ({ ...p, anims: p.anims.filter((x) => x.id !== id) })), 1600);
    });
    on<AnalyzeResult>('analyze_done', (r) => setS((p) => ({ ...p, analyzeResult: r })));
    return () => es.close();
  }, []);

  return <Ctx.Provider value={s}>{children}</Ctx.Provider>;
}
