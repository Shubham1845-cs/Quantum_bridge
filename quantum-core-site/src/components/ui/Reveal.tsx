import { cn } from '../../lib/utils';

interface RevealProps {
  children: React.ReactNode;
  /** Stagger index — higher delays the entrance. */
  index?: number;
  className?: string;
  as?: 'div' | 'section' | 'main';
}

/**
 * Lightweight entrance animation wrapper.
 * Uses the CSS `animate-qb-reveal` keyframe with an index-based delay
 * so a grid of children can stagger in without framer-motion per-item.
 */
export function Reveal({ children, index = 0, className, as = 'div' }: RevealProps) {
  const Tag = as;
  // Cap the stagger so late items don't wait forever.
  const delay = Math.min(index, 8) * 60;
  return (
    <Tag
      className={cn('animate-qb-reveal', className)}
      style={{ animationDelay: `${delay}ms` }}
    >
      {children}
    </Tag>
  );
}

export default Reveal;
