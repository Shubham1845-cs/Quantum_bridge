import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart } from 'recharts';
import { TimeseriesDataPoint } from '../../api/analytics';
import { formatDateTime } from '../../lib/utils';

interface ThreatFlagChartProps {
  data: TimeseriesDataPoint[];
}

export default function ThreatFlagChart({ data }: ThreatFlagChartProps) {
  return (
    <div className="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06] backdrop-blur-xl">
      <h3 className="text-lg font-bold text-white mb-4">Threat Detection Rate</h3>
      
      {data.length === 0 ? (
        <div className="h-[300px] flex items-center justify-center text-white/40">
          No data available
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={data}>
            <defs>
              <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
            <XAxis
              dataKey="timestamp"
              stroke="rgba(255,255,255,0.4)"
              tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 12 }}
              tickFormatter={(value) => new Date(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
            />
            <YAxis
              stroke="rgba(255,255,255,0.4)"
              tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 12 }}
              tickFormatter={(value) => `${value}%`}
              domain={[0, 100]}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#0a0a0a',
                border: '1px solid rgba(239, 68, 68, 0.2)',
                borderRadius: '8px',
                color: '#fff',
              }}
              labelFormatter={(value) => formatDateTime(value)}
              formatter={(value) => {
                const numValue = typeof value === 'number' ? value : 0;
                return [`${numValue.toFixed(1)}%`, 'Threat Rate'] as [string, string];
              }}
            />
            <Area
              type="monotone"
              dataKey="threatFlagRate"
              stroke="#ef4444"
              strokeWidth={2}
              fill="url(#threatGradient)"
              dot={{ fill: '#ef4444', r: 3 }}
              activeDot={{ r: 5, fill: '#ef4444', stroke: '#fff', strokeWidth: 2 }}
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
