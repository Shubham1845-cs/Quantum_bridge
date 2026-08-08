import { forwardRef, type HTMLAttributes } from 'react';
import { cn } from '../../lib/utils';

/**
 * Premium surface primitive — replaces the ~40× repeated
 * `bg-white/[0.02] border border-white/[0.06]` pattern across the org pages.
 *
 * Variants:
 *  - default: subtle elevated panel (lists, tables)
 *  - interactive: hovers lift + cyan hairline (cards you can click)
 *  - accent: gradient hairline ring (hero/active emphasis)
 */
type CardVariant = 'default' | 'interactive' | 'accent';

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  variant?: CardVariant;
}

const surfaces: Record<CardVariant, string> = {
  default:
    'bg-white/[0.02] border border-white/[0.07] shadow-premium-1 backdrop-blur-sm',
  interactive:
    'bg-white/[0.02] border border-white/[0.07] shadow-premium-1 backdrop-blur-sm ' +
    'transition-all duration-300 hover:-translate-y-0.5 hover:border-qb-cyan/25 ' +
    'hover:shadow-premium-3 hover:bg-white/[0.035]',
  accent:
    'bg-gradient-to-b from-white/[0.04] to-white/[0.015] border border-qb-cyan/20 shadow-premium-glow backdrop-blur-sm',
};

export const Card = forwardRef<HTMLDivElement, CardProps>(
  ({ className, variant = 'default', ...props }, ref) => (
    <div
      ref={ref}
      className={cn(
        'relative rounded-2xl',
        surfaces[variant],
        className,
      )}
      {...props}
    />
  ),
);
Card.displayName = 'Card';

export function CardHeader({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('flex items-start justify-between gap-4 px-6 pt-6', className)}
      {...props}
    />
  );
}

export function CardTitle({ className, ...props }: HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h3
      className={cn('text-base font-semibold tracking-tight text-white', className)}
      {...props}
    />
  );
}

export function CardDescription({ className, ...props }: HTMLAttributes<HTMLParagraphElement>) {
  return (
    <p className={cn('text-xs text-white/40 font-light', className)} {...props} />
  );
}

export function CardContent({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('px-6 py-5', className)} {...props} />;
}
