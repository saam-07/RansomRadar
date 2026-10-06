import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
  Legend,
} from 'recharts';

export interface TimelineDataPoint {
  timestamp: string;
  window_idx: number;
  ewma: number;
  probability: number;
  pid?: number;
  process_name?: string;
  is_containment?: boolean;
}

interface RiskTimelineChartProps {
  data: TimelineDataPoint[];
}

export const RiskTimelineChart: React.FC<RiskTimelineChartProps> = ({ data }) => {
  return (
    <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
            Process Risk Telemetry Timeline
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Streaming EWMA risk scorer score & raw ML ransomware probability with containment thresholds
          </p>
        </div>

        <div className="flex items-center space-x-3 text-xs font-mono">
          <span className="flex items-center space-x-1">
            <span className="w-2.5 h-0.5 bg-yellow-500 inline-block" />
            <span className="text-yellow-400">0.3 Elevated</span>
          </span>
          <span className="flex items-center space-x-1">
            <span className="w-2.5 h-0.5 bg-amber-500 inline-block" />
            <span className="text-amber-400">0.6 Suspicious</span>
          </span>
          <span className="flex items-center space-x-1">
            <span className="w-2.5 h-0.5 bg-red-500 inline-block" />
            <span className="text-red-400">0.85 Critical (Freeze)</span>
          </span>
        </div>
      </div>

      <div className="h-64 w-full">
        {data.length === 0 ? (
          <div className="h-full flex items-center justify-center text-slate-400 text-sm italic">
            Waiting for process telemetry windows... Run a scenario to stream live data.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis
                dataKey="window_idx"
                stroke="#64748b"
                tick={{ fontSize: 11 }}
                tickFormatter={(val) => `W${val}`}
              />
              <YAxis
                domain={[0, 1]}
                ticks={[0, 0.3, 0.6, 0.85, 1.0]}
                stroke="#64748b"
                tick={{ fontSize: 11 }}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0f172a',
                  borderColor: '#334155',
                  borderRadius: '0.5rem',
                  fontSize: '0.75rem',
                }}
                formatter={(val: any, name: any) => [
                  Number(val).toFixed(4),
                  name === 'ewma' ? 'EWMA Risk Score' : 'Raw Classifier Prob',
                ]}
                labelFormatter={(lbl) => `Window ${lbl}`}
              />
              <Legend
                verticalAlign="top"
                align="right"
                height={28}
                iconSize={8}
                wrapperStyle={{ fontSize: '11px' }}
              />

              {/* Threshold Lines */}
              <ReferenceLine y={0.3} stroke="#eab308" strokeDasharray="3 3" label={{ value: '0.3', fill: '#eab308', fontSize: 10, position: 'insideRight' }} />
              <ReferenceLine y={0.6} stroke="#f97316" strokeDasharray="3 3" label={{ value: '0.6', fill: '#f97316', fontSize: 10, position: 'insideRight' }} />
              <ReferenceLine y={0.85} stroke="#ef4444" strokeDasharray="4 4" label={{ value: '0.85 Contain', fill: '#ef4444', fontSize: 10, position: 'insideRight' }} />

              <Line
                type="monotone"
                dataKey="ewma"
                stroke="#38bdf8"
                strokeWidth={2.5}
                dot={{ r: 3, fill: '#38bdf8' }}
                activeDot={{ r: 5 }}
                name="ewma"
                isAnimationActive={false}
              />
              <Line
                type="monotone"
                dataKey="probability"
                stroke="#a855f7"
                strokeWidth={1.5}
                strokeDasharray="4 4"
                dot={false}
                name="probability"
                isAnimationActive={false}
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
};
