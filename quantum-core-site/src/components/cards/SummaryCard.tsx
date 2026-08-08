import { motion } from 'framer-motion';
import { ReactNode } from 'react';

interface SummaryCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: ReactNode;
  trend?: 'up' | 'down' | 'neutral';
  trendValue?: string;
}

export default function SummaryCard({
  title,
  value,
  subtitle,
  icon,
  trend,
  trendValue,
}: SummaryCardProps) {
  const trendColors = {
    up: 'text-green-400',
    down: 'text-red-400',
    neutral: 'text-white/40',
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06] backdrop-blur-xl hover:border-white/10 transition-colors"
    >
      <div className="flex items-start justify-between mb-4">
        <div className="text-white/40 text-xs font-bold tracking-wider uppercase">
          {title}
        </div>
        {icon && <div className="text-cyber-cyan">{icon}</div>}
      </div>
      
      <div className="text-3xl font-bold text-white mb-1">{value}</div>
      
      {subtitle && (
        <div className="text-white/40 text-sm">{subtitle}</div>
      )}
      
      {trend && trendValue && (
        <div className={`text-sm font-medium mt-2 ${trendColors[trend]}`}>
          {trend === 'up' && '↑ '}
          {trend === 'down' && '↓ '}
          {trendValue}
        </div>
      )}
    </motion.div>
  );
}
