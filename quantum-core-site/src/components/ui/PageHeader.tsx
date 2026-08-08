import { cn } from '../../lib/utils';

interface PageHeaderProps {
  title: string;
  description?: string;
  /** Rendered right-aligned — buttons, selects. */
  actions?: React.ReactNode;
  className?: string;
}

/** Consistent page heading + optional actions row for org sub-pages. */
export function PageHeader({ title, description, actions, className }: PageHeaderProps) {
  return (
    <div className={cn('mb-8 flex items-start justify-between gap-4', className)}>
      <div className="min-w-0">
        <h2 className="text-2xl font-bold tracking-tight text-white">{title}</h2>
        {description && (
          <p className="mt-1 text-sm text-white/40">{description}</p>
        )}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}

export default PageHeader;
