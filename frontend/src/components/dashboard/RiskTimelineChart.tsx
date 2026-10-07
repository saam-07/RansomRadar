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
    <div className="bg-white/85 border border-[#e5dbe8] rounded-2xl p-6 shadow-xs">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="text-sm font-semibold uppercase tracking-wider text-[#2c2436]">
            Process Risk Telemetry Timeline
          </h3>
          <p className="text-xs text-[#786c85] mt-1">
            Streaming behavioral risk telemetry & anomaly index with containment thresholds
          </p>
        </div>

        <div className="flex items-center space-x-3 text-xs font-mono">
          <span className="flex items-center space-x-1">
            <span className="w-2.5 h-0.5 bg-[#d49e35] inline-block" />
            <span className="text-[#a8761a]">0.3 Elevated</span>
          </span>
          <span className="flex items-center space-x-1">
            <span className="w-2.5 h-0.5 bg-[#d97736] inline-block" />
            <span className="text-[#b0581f]">0.6 Suspicious</span>
          </span>
          <span className="flex items-center space-x-1">
            <span className="w-2.5 h-0.5 bg-[#b54a5f] inline-block" />
            <span className="text-[#9e3348]">0.85 Critical (Freeze)</span>
          </span>
        </div>
      </div>

      <div className="h-64 w-full">
        {data.length === 0 ? (
          <div className="h-full flex items-center justify-center text-[#8c7f99] text-sm italic">
            Waiting for process telemetry windows... Run a scenario to stream live data.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#ede4ef" />
              <XAxis
                dataKey="window_idx"
                stroke="#8c7f99"
                tick={{ fontSize: 11 }}
                tickFormatter={(val) => `W${val}`}
              />
              <YAxis
                domain={[0, 1]}
                ticks={[0, 0.3, 0.6, 0.85, 1.0]}
                stroke="#8c7f99"
                tick={{ fontSize: 11 }}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#ffffff',
                  borderColor: '#e2d5e6',
                  borderRadius: '0.5rem',
                  fontSize: '0.75rem',
                  color: '#2c2436',
                  boxShadow: '0 4px 14px rgba(90, 70, 100, 0.08)',
                }}
                formatter={(val: any, name: any) => [
                  Number(val).toFixed(4),
                  name === 'ewma' || name === 'Risk Score' ? 'Risk Score' : 'Behavioral Anomaly Index',
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
              <ReferenceLine y={0.3} stroke="#d49e35" strokeDasharray="3 3" label={{ value: '0.3', fill: '#a8761a', fontSize: 10, position: 'insideRight' }} />
              <ReferenceLine y={0.6} stroke="#d97736" strokeDasharray="3 3" label={{ value: '0.6', fill: '#b0581f', fontSize: 10, position: 'insideRight' }} />
              <ReferenceLine y={0.85} stroke="#b54a5f" strokeDasharray="4 4" label={{ value: '0.85 Contain', fill: '#9e3348', fontSize: 10, position: 'insideRight' }} />

              <Line
                type="monotone"
                dataKey="ewma"
                stroke="#5b82a6"
                strokeWidth={2.5}
                dot={{ r: 3, fill: '#5b82a6' }}
                activeDot={{ r: 5 }}
                name="Risk Score"
                isAnimationActive={false}
              />
              <Line
                type="monotone"
                dataKey="probability"
                stroke="#b56576"
                strokeWidth={1.5}
                strokeDasharray="4 4"
                dot={false}
                name="Behavioral Anomaly"
                isAnimationActive={false}
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
};
