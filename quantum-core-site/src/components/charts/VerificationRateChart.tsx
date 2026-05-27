import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { TimeseriesDataPoint } from '../../api/analytics';
import { formatDateTime } from '../../lib/utils';

interface VerificationRateChartProps {
  data: TimeseriesDataPoint[];
}

export default function VerificationRateChart({ data }: VerificationRateChartProps) {
  return (
    <div className="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06] backdrop-blur-xl">
      <h3 className="text-lg font-bold text-white mb-4">Signature Verification Rates</h3>
      
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
              tickFormatter={(value) => `${value}%`}
              domain={[0, 100]}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#0a0a0a',
                border: '1px solid rgba(0, 255, 255, 0.2)',
                borderRadius: '8px',
                color: '#fff',
              }}
              labelFormatter={(value) => formatDateTime(value)}
              formatter={(value) => {
                const numValue = typeof value === 'number' ? value : 0;
                return [`${numValue.toFixed(1)}%`, ''] as [string, string];
              }}
            />
            <Legend
              wrapperStyle={{ color: 'rgba(255,255,255,0.6)', fontSize: '12px' }}
              iconType="line"
            />
            <Line
              type="monotone"
              dataKey="ecdsaVerificationRate"
              name="ECDSA P-256"
              stroke="#00FFFF"
              strokeWidth={2}
              dot={{ fill: '#00FFFF', r: 3 }}
              activeDot={{ r: 5, fill: '#00FFFF', stroke: '#fff', strokeWidth: 2 }}
            />
            <Line
              type="monotone"
              dataKey="dilithiumVerificationRate"
              name="ML-DSA-65"
              stroke="#8A2BE2"
              strokeWidth={2}
              dot={{ fill: '#8A2BE2', r: 3 }}
              activeDot={{ r: 5, fill: '#8A2BE2', stroke: '#fff', strokeWidth: 2 }}
            />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
