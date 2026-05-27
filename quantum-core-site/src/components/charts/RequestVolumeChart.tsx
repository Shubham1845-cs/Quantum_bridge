import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { TimeseriesDataPoint } from '../../api/analytics';
import { formatDateTime } from '../../lib/utils';

interface RequestVolumeChartProps {
  data: TimeseriesDataPoint[];
}

export default function RequestVolumeChart({ data }: RequestVolumeChartProps) {
  return (
    <div className="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06] backdrop-blur-xl">
      <h3 className="text-lg font-bold text-white mb-4">Request Volume</h3>
      
      {data.length === 0 ? (
        <div className="h-[300px] flex items-center justify-center text-white/40">
          No data available
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={data}>
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
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#0a0a0a',
                border: '1px solid rgba(0, 255, 255, 0.2)',
                borderRadius: '8px',
                color: '#fff',
              }}
              labelFormatter={(value) => formatDateTime(value)}
              formatter={(value) => [value ?? 0, 'Requests'] as [number, string]}
            />
            <Line
              type="monotone"
              dataKey="requestCount"
              stroke="#00FFFF"
              strokeWidth={2}
              dot={{ fill: '#00FFFF', r: 4 }}
              activeDot={{ r: 6, fill: '#00FFFF', stroke: '#fff', strokeWidth: 2 }}
            />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
