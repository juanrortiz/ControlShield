import { useEffect, useRef } from 'react';
import type { AppState } from '@/api';
import type { Anim } from '@/store';
import { TAG_TEXT } from '@/ui';

// SVG user units (the diagram scales with its container)
const W = 1000, H = 420;
const POS: Record<string, [number, number]> = {
  hmi: [140, 80], laptop: [140, 210], attacker: [140, 340], guardian: [510, 210], plc: [870, 210],
};
const ACTOR_COLOR: Record<string, string> = { hmi: 'text-information-base', laptop: 'text-teal-500', attacker: 'text-error-base' };
const ACTOR_LABEL: Record<string, [string, string]> = {
  hmi: ['HMI', '127.0.0.10'], laptop: ['Engineering laptop', '127.0.0.2'], attacker: ['Attacker', '127.0.0.99'],
};

function Packet({ anim }: { anim: Anim }) {
  const ref = useRef<SVGGElement>(null);
  useEffect(() => {
    const a = POS[anim.actor], g = POS.guardian, p = POS.plc;
    const pts = anim.direct ? [a, p] : anim.blocked ? [a, g] : [a, g, p];
    const seg = 380, total = seg * (pts.length - 1), t0 = performance.now();
    let raf = 0;
    const step = (now: number) => {
      const t = Math.min(now - t0, total);
      const i = Math.min(Math.floor(t / seg), pts.length - 2);
      const f = (t - i * seg) / seg;
      const x = pts[i][0] + (pts[i + 1][0] - pts[i][0]) * f;
      const y = pts[i][1] + (pts[i + 1][1] - pts[i][1]) * f;
      ref.current?.setAttribute('transform', `translate(${x} ${y})`);
      if (now - t0 < total + 650) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [anim]);
  const done = anim.blocked ? 'opacity-100' : '';
  return (
    <g ref={ref} className={TAG_TEXT[anim.tag] ?? 'text-success-base'} transform={`translate(${POS[anim.actor][0]} ${POS[anim.actor][1]})`}>
      <circle r='11' className='fill-current stroke-white-0' strokeWidth='2.5' />
      {anim.blocked && <g className={`${done} animate-in fade-in`}><text y='-26' x='0' textAnchor='middle' className='fill-current text-label-md'>✖ BLOCKED</text></g>}
    </g>
  );
}

export function Topology({ state, anims }: { state: AppState; anims: Anim[] }) {
  const on = state.route === 'on';
  const modeText = state.mode === 'block' ? 'text-success-base' : 'text-warning-base';
  const locked = !!state.plc?.coils[7];
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className='h-full w-full' role='img' aria-label='Traffic path: clients, Guardian, PLC'>
      {/* links */}
      {Object.keys(ACTOR_COLOR).map((k) => (
        <line key={k} x1={POS[k][0]} y1={POS[k][1]} x2={(on ? POS.guardian : POS.plc)[0]} y2={(on ? POS.guardian : POS.plc)[1]}
          className={`${ACTOR_COLOR[k]} stroke-current`} strokeWidth='2.5' strokeDasharray={on ? undefined : '9 7'} opacity={on ? 0.7 : 0.55} />
      ))}
      {on && <line x1={POS.guardian[0]} y1={POS.guardian[1]} x2={POS.plc[0]} y2={POS.plc[1]} className={`${modeText} stroke-current`} strokeWidth='4' />}

      {/* clients */}
      {Object.keys(ACTOR_COLOR).map((k) => {
        const [x, y] = POS[k];
        const allowed = k !== 'attacker' || state.allow_attacker;
        return (
          <g key={k}>
            <rect x={x - 112} y={y - 36} width='224' height='72' rx='16' className={`${ACTOR_COLOR[k]} fill-bg-weak-50 stroke-current`} strokeWidth='2' />
            <text x={x} y={y - 6} textAnchor='middle' className='fill-text-strong-950 text-label-md'>{ACTOR_LABEL[k][0]}</text>
            <text x={x} y={y + 18} textAnchor='middle' className={`${allowed ? 'fill-success-base' : 'fill-error-base'} text-paragraph-sm`}>
              {ACTOR_LABEL[k][1]} · {allowed ? 'allowlisted' : 'NOT allowlisted'}
            </text>
          </g>
        );
      })}

      {/* guardian */}
      <g>
        <rect x={POS.guardian[0] - 125} y={POS.guardian[1] - 88} width='250' height='176' rx='20'
          className={`${on ? modeText : 'text-text-soft-400'} fill-bg-weak-50 stroke-current`} strokeWidth='3.5' strokeDasharray={on ? undefined : '10 8'} />
        <text x={POS.guardian[0]} y={POS.guardian[1] - 44} textAnchor='middle' className='fill-text-strong-950 text-label-lg'>PLC GUARDIAN</text>
        <text x={POS.guardian[0]} y={POS.guardian[1] - 10} textAnchor='middle' className={`${on ? modeText : 'text-text-soft-400'} fill-current text-label-md`}>
          {on ? (state.mode === 'block' ? 'BLOCK mode' : 'MONITOR mode') : 'BYPASSED'}
        </text>
        <text x={POS.guardian[0]} y={POS.guardian[1] + 20} textAnchor='middle' className='fill-text-sub-600 text-paragraph-sm'>
          {on ? 'checks · logs · blocks' : 'not in the path'}
        </text>
        {on && state.lockout && (
          <text x={POS.guardian[0]} y={POS.guardian[1] + 54} textAnchor='middle' className='fill-purple-500 text-paragraph-sm'>auto-lockout armed</text>
        )}
      </g>

      {/* plc */}
      <g>
        <rect x={POS.plc[0] - 100} y={POS.plc[1] - 66} width='200' height='132' rx='18'
          className={`${locked ? 'text-purple-500' : 'text-information-base'} fill-bg-weak-50 stroke-current`} strokeWidth='3.5' />
        <text x={POS.plc[0]} y={POS.plc[1] - 28} textAnchor='middle' className='fill-text-strong-950 text-label-lg'>PLC</text>
        <text x={POS.plc[0]} y={POS.plc[1] - 2} textAnchor='middle' className='fill-text-sub-600 text-paragraph-sm'>simulated tank</text>
        <text x={POS.plc[0]} y={POS.plc[1] + 32} textAnchor='middle' className={`${locked ? 'fill-purple-500' : 'fill-text-strong-950'} text-label-md`}>
          {locked ? 'LOCKED OUT' : state.plc ? `level ${state.plc.level}` : 'offline'}
        </text>
      </g>

      {anims.map((a) => <Packet key={a.id} anim={a} />)}
    </svg>
  );
}
