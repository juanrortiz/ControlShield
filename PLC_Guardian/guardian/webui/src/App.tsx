import { useEffect, useState, type ComponentType } from 'react';
import { RiPlayCircleLine, RiQuestionLine, RiRadarLine, RiSearchEyeLine, RiShieldCheckLine } from '@remixicon/react';
import * as Badge from '@/components/ui/badge';
import * as StatusBadge from '@/components/ui/status-badge';
import { cn } from '@/utils/cn';
import { useGuardian } from './store';
import Demo from './screens/Demo';
import Lab from './screens/Lab';
import Analyze from './screens/Analyze';
import Evidence from './screens/Evidence';
import Help from './screens/Help';

type Screen = 'demo' | 'lab' | 'analyze' | 'evidence' | 'help';

const NAV: { id: Screen; label: string; icon: ComponentType<{ className?: string }>; badge?: { text: string; color: 'blue' | 'orange' } }[] = [
  { id: 'demo', label: 'Live Demo', icon: RiPlayCircleLine, badge: { text: 'Safe', color: 'blue' } },
  { id: 'lab', label: 'Lab Mode', icon: RiRadarLine, badge: { text: 'Real', color: 'orange' } },
  { id: 'analyze', label: 'Analyze Captures', icon: RiSearchEyeLine },
  { id: 'evidence', label: 'Evidence', icon: RiShieldCheckLine },
  { id: 'help', label: 'Help', icon: RiQuestionLine },
];

const SYSTEM_BADGE = {
  stopped: ['disabled', 'Demo stopped'],
  starting: ['pending', 'Demo starting…'],
  running: ['completed', 'Demo running'],
  stopping: ['pending', 'Demo stopping…'],
} as const;

export default function App() {
  const { state, connected } = useGuardian();
  const [screen, setScreen] = useState<Screen>('demo');
  const [auto, setAuto] = useState(false);

  useEffect(() => {
    const onGoto = (e: Event) => {
      if ((e as CustomEvent).detail === 'evidence') {
        setScreen('evidence');
        setAuto(true);
      }
    };
    window.addEventListener('guardian:goto', onGoto);
    return () => window.removeEventListener('guardian:goto', onGoto);
  }, []);

  const [status, statusText] = SYSTEM_BADGE[state?.system ?? 'stopped'];
  const show = (id: Screen) => (screen === id ? 'block' : 'hidden');

  return (
    <div className='flex h-screen bg-bg-white-0 text-text-strong-950'>
      <aside className='flex w-60 shrink-0 flex-col border-r border-stroke-soft-200 bg-bg-weak-50'>
        <div className='px-5 pb-4 pt-5'>
          <div className='text-label-lg tracking-wide text-text-strong-950'>PLC GUARD</div>
          <div className='mt-0.5 text-paragraph-xs text-text-sub-600'>Network forensics · ECE4311</div>
        </div>
        <div className='px-5 pb-1.5 text-subheading-2xs uppercase text-text-soft-400'>Explore</div>
        <nav className='flex flex-col gap-0.5 px-3'>
          {NAV.map(({ id, label, icon: Icon, badge }) => (
            <button
              key={id}
              onClick={() => setScreen(id)}
              aria-current={screen === id ? 'page' : undefined}
              className={cn(
                'flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-label-sm transition duration-200 ease-out',
                screen === id ? 'bg-bg-white-0 text-text-strong-950 shadow-regular-xs ring-1 ring-inset ring-stroke-soft-200' : 'text-text-sub-600 hover:bg-bg-white-0/60 hover:text-text-strong-950',
              )}
            >
              <Icon className={cn('size-5', screen === id ? 'text-primary-base' : 'text-text-soft-400')} />
              <span className='flex-1'>{label}</span>
              {badge && <Badge.Root variant='light' color={badge.color} size='small'>{badge.text}</Badge.Root>}
            </button>
          ))}
        </nav>
        <div className='mt-auto flex flex-col gap-2 border-t border-stroke-soft-200 px-5 py-4'>
          <StatusBadge.Root status={status} variant='light' className='w-fit'>
            <StatusBadge.Dot />
            {statusText}
          </StatusBadge.Root>
          <div className='flex items-center gap-2 text-paragraph-xs text-text-sub-600'>
            <span className={cn('size-2 rounded-full', connected ? 'bg-success-base' : 'animate-pulse bg-warning-base')} />
            {connected ? 'Connected' : 'Reconnecting…'}
          </div>
          <div className='text-paragraph-xs text-text-soft-400'>Isolated lab · evidence is read-only</div>
        </div>
      </aside>

      <main className='min-w-0 flex-1 overflow-auto p-5'>
        <div className='mx-auto max-w-[1500px]'>
          <div className={show('demo')}><Demo /></div>
          <div className={show('lab')}><Lab /></div>
          <div className={show('analyze')}><Analyze /></div>
          <div className={show('evidence')}><Evidence auto={auto} onAutoDone={() => setAuto(false)} /></div>
          <div className={show('help')}><Help /></div>
        </div>
      </main>
    </div>
  );
}
