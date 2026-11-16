import type { ReactNode } from 'react';
import * as Accordion from '@/components/ui/accordion';
import { PageTitle, VerdictBadge, mono } from '@/ui';

const P = ({ children }: { children: ReactNode }) => <p className='mb-2 last:mb-0'>{children}</p>;
const UL = ({ children }: { children: ReactNode }) => <ul className='mb-2 list-disc space-y-1 pl-5 last:mb-0'>{children}</ul>;

const verdicts: [string, string, string][] = [
  ['allow', 'allowed', 'An allowlisted source doing something it is permitted to do.'],
  ['alert', 'ALERT (allowed)', 'Permitted but suspicious (e.g. an authorized host turning on the maintenance bypass). Never blocked, never triggers the lockout.'],
  ['detect', 'DETECTED, not stopped', 'A BLOCK-grade event, but Guardian was only monitoring, so it was forwarded to the PLC. Evidence without prevention.'],
  ['block', 'BLOCKED', 'Guardian refused it with a Modbus exception; the PLC never saw it.'],
  ['lock', 'LOCKOUT SUCCEEDED', 'Guardian itself wrote coil %M7 on the PLC after seeing an attack (D-007). The PLC program uses it to halt the process.'],
  ['bypass', 'no Guardian', 'Guardian was switched off in the demo: the request went straight to the PLC and nothing was checked or logged.'],
];

const sections: { id: string; title: string; body: ReactNode }[] = [
  {
    id: 'what', title: 'What is PLC Guardian?',
    body: (
      <P>
        A monitor and enforcer for Modbus/TCP traffic between an HMI and a Schneider M221 PLC. Every request is judged by a policy,
        written to a tamper-evident log and, optionally, blocked.
      </P>
    ),
  },
  {
    id: 'layers', title: 'The four layers (and where to see them)',
    body: (
      <>
        <P><strong>1 Detect → 2 Log → 3 Block → 4 React</strong></P>
        <UL>
          <li><strong>Detect</strong>: {mono('policy.py')} decides ALLOW / ALERT / BLOCK for each request.</li>
          <li><strong>Log</strong>: {mono('evidence_log.py')} writes an append-only JSONL log chained with SHA-256 (see the Evidence screen).</li>
          <li><strong>Block</strong>: {mono('proxy.py')} refuses the request when Guardian is inline.</li>
          <li><strong>React</strong>: {mono('active_response.py')} writes a lockout coil on the PLC when Guardian can only watch (D-007).</li>
        </UL>
      </>
    ),
  },
  {
    id: 'feed', title: 'Reading the feed',
    body: (
      <ul className='space-y-2'>
        {verdicts.map(([tag, label, text]) => (
          <li key={tag} className='flex flex-wrap items-start gap-3'>
            <span className='w-48 shrink-0'><VerdictBadge tag={tag}>{label}</VerdictBadge></span>
            <span className='min-w-0 flex-1'>{text}</span>
          </li>
        ))}
      </ul>
    ),
  },
  {
    id: 'demo', title: 'Live Demo',
    body: (
      <>
        <P>
          Everything runs on this machine. Clients bind to {mono('127.0.0.10')} (HMI), {mono('127.0.0.2')} (engineering laptop) and {mono('127.0.0.99')} (attacker)
          so Guardian sees different source IPs. Guardian listens on port {mono('5502')} and forwards to a simulated PLC on port {mono('5020')}. The demo
          allowlist and protected points come from {mono('guardian/demo/config.json')} (the protected points are copied from the real {mono('config.json')}).
        </P>
        <UL>
          <li><strong>Guardian ON/OFF</strong>: clients go through the proxy, or straight to the PLC.</li>
          <li><strong>Monitor/Block</strong>: changes {mono('enforcement.mode')} in the demo config; the proxy hot-reloads it on the next request.</li>
          <li><strong>Auto-lockout</strong>: the server hosts a real {mono('ActiveResponder')} that fires on BLOCK-grade events (the real monitor does the same from its sniffer).</li>
          <li><strong>Allowlist attacker</strong>: adds 127.0.0.99 as read-only, live. Its reads then pass; its writes are still refused.</li>
          <li><strong>Reset PLC</strong> (the tour does this between steps): writes zeros straight to the simulated PLC, bypassing Guardian. It is not an attack.</li>
        </UL>
        <P>
          The tank is an <strong>ILLUSTRATIVE</strong> simulation modelled on the documented behaviour (Start fills, level-80 stop, bypass %M4 defeats it,
          overload above 100, Reset empties). The fill rate and the lockout's effect are not measurements of the real PLC.
        </P>
      </>
    ),
  },
  {
    id: 'lab', title: 'Lab Mode',
    body: (
      <P>
        Runs the real {mono('guardian.py')} commands (monitor, proxy, httpgate) against the lab network and edits the live flags in {mono('guardian/config.json')}.
        Each run writes a fresh log in {mono('guardian/logs/gui_<cmd>_<time>.jsonl')} (never an existing file). The passive monitor can only detect and react;
        true prevention needs Guardian inline (D-003 / A-004). Lab Mode is switched off inside Docker.
      </P>
    ),
  },
  {
    id: 'analyze', title: 'Analyze Captures',
    body: (
      <P>
        Runs analyze / forensics / baseline on a capture. The capture is only read; its SHA-256 is shown before and after. Outputs go to {mono('guardian/logs/')} and
        {' '}{mono('guardian/reports/gui_<capture>_<time>/')}.
      </P>
    ),
  },
  {
    id: 'evidence', title: 'Evidence',
    body: (
      <P>
        Verify a log's hash chain, export it to CSV, or tamper with a <strong>copy</strong> to prove edits are detected. The original log is never changed.
      </P>
    ),
  },
];

export default function Help() {
  return (
    <div className='flex flex-col gap-3'>
      <PageTitle title='Help' sub='What every concept on screen means.' />
      <Accordion.Root type='single' collapsible defaultValue={sections[0].id} className='flex flex-col gap-2'>
        {sections.map((s) => (
          <Accordion.Item key={s.id} value={s.id}>
            <Accordion.Trigger>
              {s.title}
              <Accordion.Arrow className='ml-auto' />
            </Accordion.Trigger>
            <Accordion.Content>{s.body}</Accordion.Content>
          </Accordion.Item>
        ))}
      </Accordion.Root>
    </div>
  );
}
