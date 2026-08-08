import type { LucideIcon } from 'lucide-react';
import { cn } from '../../lib/utils';
import { Card } from './Card';

type Tone = 'cyan' | 'violet' | 'emerald' | 'amber' | 'rose';

// Full literal class strings so Tailwind's JIT scanner generates every one
// (string-concat class names like `accent.replace('text-','bg-')` are invisible
//  to the scanner and silently produce no styles).
const TONE: Record<Tone, { text: string; bg: string; border: string }> = {
  cyan:    { text: 'text-qb-cyan',    bg: 'bg-qb-cyan',    border: 'border-qb-cyan/25'    },
  violet:  { text: 'text-qb-violet',  bg: 'bg-qb-violet',  border: 'border-qb-violet/25'  },
  emerald: { text: 'text-qb-emerald', bg: 'bg-qb-emerald', border: 'border-qb-emerald/25' },
  amber:   { text: 'text-qb-amber',   bg: 'bg-qb-amber',   border: 'border-qb-amber/25'   },
  rose:    { text: 'text-qb-rose',    bg: 'bg-qb-rose',    border: 'border-qb-rose/25'    },
};

interface StatCardProps {
  label: string;
  value: React.ReactNode;
  hint?: string;
  icon?: LucideIcon;
  tone?: Tone;
  /** Optional trend delta, e.g. '+12%'. Renders green/red via sign. */
  delta?: string;
  loading?: boolean;
  className?: string;
}

export function StatCard({
  label,
  value,
  hint,
  icon: Icon,
  tone = 'cyan',
  delta,
  loading = false,
  className,
}: StatCardProps) {
  const palette = TONE[tone];
  const deltaUp = delta?.trim().startsWith('+');

  return (
    <Card variant="interactive" className={cn('group overflow-hidden', className)}>
      {/* radial accent glow that brightens on hover */}
      <div
        className={cn(
          'pointer-events-none absolute -right-10 -top-10 h-28 w-28 rounded-full opacity-[0.07] blur-2xl transition-opacity duration-300 group-hover:opacity-[0.14]',
          palette.bg,
        )}
      />
      <div className="relative flex items-start justify-between p-5">
        <div className="min-w-0">
          <p className="text-[10px] font-medium uppercase tracking-[0.22em] text-white/40">
            {label}
          </p>
          <div className={cn('mt-2 text-3xl font-bold tracking-tight', palette.text)}>
            {loading ? '—' : value}
          </div>
          {hint && <p className="mt-1 text-[11px] text-white/30">{hint}</p>}
          {delta && (
            <span
              className={cn(
                'mt-2 inline-flex items-center gap-1 text-[11px] font-medium',
                deltaUp ? 'text-qb-emerald' : 'text-qb-rose',
              )}
            >
              {deltaUp ? '▲' : '▼'} {delta}
            </span>
          )}
        </div>
        {Icon && (
          <div
            className={cn(
              'flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border bg-white/[0.03]',
              palette.text,
              palette.border,
            )}
          >
            <Icon size={18} />
          </div>
        )}
      </div>
    </Card>
  );
}

export default StatCard;
