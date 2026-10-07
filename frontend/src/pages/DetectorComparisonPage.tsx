import React, { useState, useEffect } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import {
  BarChart3,
  Play,
  RotateCcw,
  ShieldCheck,
  ShieldAlert,
  Clock,
  FileCheck2,
  AlertTriangle,
  Layers,
  Cpu,
  Sparkles,
} from 'lucide-react';
import { api } from '../api/client';
import { ScenarioDefinition } from '../types/api';

interface DetectorMetrics {
  detector: string;
  total_windows: number;
  time_to_detect_windows: number | null;
  time_to_detect_seconds: number | null;
  contained_pids: number[];
  files_lost: number;
  files_saved: number;
  files_restored: number;
  false_alarms: number;
}

export const DetectorComparisonPage: React.FC = () => {
  const [scenarios, setScenarios] = useState<ScenarioDefinition[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<string>('fast_ransomware');
  const [seed, setSeed] = useState<number>(42);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [comparisonData, setComparisonData] = useState<Record<string, DetectorMetrics> | null>(null);

  // Load scenarios on mount
  useEffect(() => {
    api
      .getScenarios()
      .then((data) => {
        setScenarios(data);
        if (data.length > 0 && !selectedScenario) {
          setSelectedScenario(data[0].name);
        }
      })
      .catch((err) => {
        console.error('Failed to load scenarios:', err);
      });
  }, []);

  const handleRunComparison = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.compareDetectors({
        scenario_name: selectedScenario,
        seed,
      });
      setComparisonData(res.comparison);
    } catch (err: any) {
      setError(err.message || 'Comparison execution failed');
    } finally {
      setLoading(false);
    }
  };

  // Run on mount once or when scenario changes if already run
  useEffect(() => {
    handleRunComparison();
  }, []);

  // Format chart data
  const chartData = comparisonData
    ? [
        {
          name: 'Rule-Based Heuristic',
          detectorKey: 'rule_based',
          detectionDelay: comparisonData.rule_based?.time_to_detect_seconds ?? 0,
          filesLost: comparisonData.rule_based?.files_lost ?? 0,
          filesRestored: comparisonData.rule_based?.files_restored ?? 0,
          falseAlarms: comparisonData.rule_based?.false_alarms ?? 0,
        },
        {
          name: 'Random Forest (Tier-1)',
          detectorKey: 'random_forest',
          detectionDelay: comparisonData.random_forest?.time_to_detect_seconds ?? 0,
          filesLost: comparisonData.random_forest?.files_lost ?? 0,
          filesRestored: comparisonData.random_forest?.files_restored ?? 0,
          falseAlarms: comparisonData.random_forest?.false_alarms ?? 0,
        },
        {
          name: 'XGBoost Boosted Trees',
          detectorKey: 'xgboost',
          detectionDelay: comparisonData.xgboost?.time_to_detect_seconds ?? 0,
          filesLost: comparisonData.xgboost?.files_lost ?? 0,
          filesRestored: comparisonData.xgboost?.files_restored ?? 0,
          falseAlarms: comparisonData.xgboost?.false_alarms ?? 0,
        },
      ]
    : [];

  const getDetectorBadge = (key: string) => {
    switch (key) {
      case 'rule_based':
        return <span className="px-2 py-0.5 rounded text-xs bg-[#f2e9f2] text-[#6b5f77] border border-[#e0d3e5]">Static Threshold</span>;
      case 'random_forest':
        return <span className="px-2 py-0.5 rounded text-xs bg-[#eaf0f8] text-[#3d5c85] border border-[#c8d8ec]">Ensemble 100 Trees</span>;
      case 'xgboost':
        return <span className="px-2 py-0.5 rounded text-xs bg-[#eddce5] text-[#9d7394] border border-[#dcbcd1]">Gradient Boosted</span>;
      default:
        return null;
    }
  };

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-2xl font-bold text-[#2c2436] tracking-tight">Detection Analysis</h1>
            <span className="px-2 py-0.5 rounded text-xs font-mono bg-[#eddce5] text-[#9d7394] border border-[#dcbcd1]">
              Detector Comparison Benchmark
            </span>
          </div>
          <p className="text-sm text-[#786c85] mt-1">
            Run the identical scenario against Rule-based, Random Forest, and XGBoost detectors with deterministic seeding.
          </p>
        </div>

        {/* Controls Toolbar */}
        <div className="flex flex-wrap items-center gap-3 bg-white/85 p-2 rounded-xl border border-[#e5dbe8] shadow-sm">
          <div className="flex items-center space-x-2">
            <label className="text-xs text-[#786c85] font-medium">Scenario:</label>
            <select
              value={selectedScenario}
              onChange={(e) => setSelectedScenario(e.target.value)}
              className="bg-[#fcfaf8] border border-[#d8c8dc] text-[#2c2436] text-xs rounded-lg px-2.5 py-1.5 focus:ring-1 focus:ring-[#b56576] focus:outline-none"
            >
              {scenarios.map((s) => (
                <option key={s.name} value={s.name}>
                  {s.name.replace(/_/g, ' ').toUpperCase()} ({s.family})
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center space-x-2">
            <label className="text-xs text-[#786c85] font-medium">Seed:</label>
            <input
              type="number"
              value={seed}
              onChange={(e) => setSeed(parseInt(e.target.value) || 42)}
              className="w-16 bg-[#fcfaf8] border border-[#d8c8dc] text-[#2c2436] text-xs rounded-lg px-2.5 py-1.5 font-mono focus:ring-1 focus:ring-[#b56576] focus:outline-none"
            />
          </div>

          <button
            onClick={handleRunComparison}
            disabled={loading}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-[#b56576] hover:bg-[#a25364] text-white text-xs font-semibold shadow-sm transition-colors disabled:opacity-50"
          >
            {loading ? (
              <>
                <RotateCcw className="w-3.5 h-3.5 animate-spin" />
                <span>Benchmarking...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Run Side-by-Side</span>
              </>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-[#fdecee] border border-[#f8c4cd] flex items-center space-x-3 text-[#9e3146] text-sm">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Side-by-Side KPI Cards */}
      {comparisonData && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {/* Rule-Based Card */}
          {comparisonData.rule_based && (
            <div className="rounded-xl bg-white/85 border border-[#e5dbe8] shadow-sm p-5 space-y-4 hover:border-[#d4c4d8] transition-all">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Layers className="w-4 h-4 text-[#786c85]" />
                  <h3 className="font-semibold text-[#2c2436] text-sm">Rule-Based Heuristic</h3>
                </div>
                {getDetectorBadge('rule_based')}
              </div>

              <div className="grid grid-cols-2 gap-3 pt-1">
                <div className="p-3 rounded-lg bg-[#fcfaf8] border border-[#ebdbe8]">
                  <div className="flex items-center space-x-1.5 text-xs text-[#786c85] mb-1">
                    <Clock className="w-3 h-3 text-[#d49e35]" />
                    <span>Time to Detect</span>
                  </div>
                  <div className="text-lg font-bold font-mono text-[#2c2436]">
                    {comparisonData.rule_based.time_to_detect_seconds !== null
                      ? `${comparisonData.rule_based.time_to_detect_seconds.toFixed(1)}s`
                      : 'None'}
                  </div>
                  <div className="text-[11px] text-[#8c7f99]">
                    {comparisonData.rule_based.time_to_detect_windows !== null
                      ? `window #${comparisonData.rule_based.time_to_detect_windows}`
                      : 'Not triggered'}
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-[#fcfaf8] border border-[#ebdbe8]">
                  <div className="flex items-center space-x-1.5 text-xs text-[#786c85] mb-1">
                    <AlertTriangle className="w-3 h-3 text-[#b54a5f]" />
                    <span>Files Lost</span>
                  </div>
                  <div className={`text-lg font-bold font-mono ${comparisonData.rule_based.files_lost > 0 ? 'text-[#9e3146]' : 'text-[#246e40]'}`}>
                    {comparisonData.rule_based.files_lost}
                  </div>
                  <div className="text-[11px] text-[#8c7f99]">
                    {comparisonData.rule_based.files_restored} restored via rollback
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-[#fcfaf8] border border-[#ebdbe8]">
                  <div className="flex items-center space-x-1.5 text-xs text-[#786c85] mb-1">
                    <ShieldAlert className="w-3 h-3 text-[#d49e35]" />
                    <span>False Alarms</span>
                  </div>
                  <div className={`text-lg font-bold font-mono ${comparisonData.rule_based.false_alarms > 0 ? 'text-[#9b5825]' : 'text-[#246e40]'}`}>
                    {comparisonData.rule_based.false_alarms}
                  </div>
                  <div className="text-[11px] text-[#8c7f99]">Benign contained</div>
                </div>

                <div className="p-3 rounded-lg bg-[#fcfaf8] border border-[#ebdbe8]">
                  <div className="flex items-center space-x-1.5 text-xs text-[#786c85] mb-1">
                    <FileCheck2 className="w-3 h-3 text-[#246e40]" />
                    <span>Files Preserved</span>
                  </div>
                  <div className="text-lg font-bold font-mono text-[#246e40]">
                    {comparisonData.rule_based.files_saved}
                  </div>
                  <div className="text-[11px] text-[#8c7f99]">Intact + recovered</div>
                </div>
              </div>

              <div className="pt-2 border-t border-[#ebdbe8] text-xs text-[#786c85] flex items-center justify-between">
                <span>Contained PIDs:</span>
                <span className="font-mono text-[#4a3f55]">
                  {comparisonData.rule_based.contained_pids.length > 0
                    ? comparisonData.rule_based.contained_pids.join(', ')
                    : 'None'}
                </span>
              </div>
            </div>
          )}

          {/* Random Forest Card */}
          {comparisonData.random_forest && (
            <div className="rounded-xl bg-white/85 border border-[#d2def0] shadow-sm p-5 space-y-4 hover:border-[#b8cce6] transition-all relative overflow-hidden">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Cpu className="w-4 h-4 text-[#3d5c85]" />
                  <h3 className="font-semibold text-[#2c2436] text-sm">Random Forest</h3>
                </div>
                {getDetectorBadge('random_forest')}
              </div>

              <div className="grid grid-cols-2 gap-3 pt-1">
                <div className="p-3 rounded-lg bg-[#f4f7fb] border border-[#d8e3f2]">
                  <div className="flex items-center space-x-1.5 text-xs text-[#786c85] mb-1">
                    <Clock className="w-3 h-3 text-[#d49e35]" />
                    <span>Time to Detect</span>
                  </div>
                  <div className="text-lg font-bold font-mono text-[#2c2436]">
                    {comparisonData.random_forest.time_to_detect_seconds !== null
                      ? `${comparisonData.random_forest.time_to_detect_seconds.toFixed(1)}s`
                      : 'None'}
                  </div>
                  <div className="text-[11px] text-[#8c7f99]">
                    {comparisonData.random_forest.time_to_detect_windows !== null
                      ? `window #${comparisonData.random_forest.time_to_detect_windows}`
                      : 'Not triggered'}
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-[#f4f7fb] border border-[#d8e3f2]">
                  <div className="flex items-center space-x-1.5 text-xs text-[#786c85] mb-1">
                    <AlertTriangle className="w-3 h-3 text-[#b54a5f]" />
                    <span>Files Lost</span>
                  </div>
                  <div className={`text-lg font-bold font-mono ${comparisonData.random_forest.files_lost > 0 ? 'text-[#9e3146]' : 'text-[#246e40]'}`}>
                    {comparisonData.random_forest.files_lost}
                  </div>
                  <div className="text-[11px] text-[#8c7f99]">
                    {comparisonData.random_forest.files_restored} restored via rollback
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-[#f4f7fb] border border-[#d8e3f2]">
                  <div className="flex items-center space-x-1.5 text-xs text-[#786c85] mb-1">
                    <ShieldAlert className="w-3 h-3 text-[#d49e35]" />
                    <span>False Alarms</span>
                  </div>
                  <div className={`text-lg font-bold font-mono ${comparisonData.random_forest.false_alarms > 0 ? 'text-[#9b5825]' : 'text-[#246e40]'}`}>
                    {comparisonData.random_forest.false_alarms}
                  </div>
                  <div className="text-[11px] text-[#8c7f99]">Benign contained</div>
                </div>

                <div className="p-3 rounded-lg bg-[#f4f7fb] border border-[#d8e3f2]">
                  <div className="flex items-center space-x-1.5 text-xs text-[#786c85] mb-1">
                    <FileCheck2 className="w-3 h-3 text-[#246e40]" />
                    <span>Files Preserved</span>
                  </div>
                  <div className="text-lg font-bold font-mono text-[#246e40]">
                    {comparisonData.random_forest.files_saved}
                  </div>
                  <div className="text-[11px] text-[#8c7f99]">Intact + recovered</div>
                </div>
              </div>

              <div className="pt-2 border-t border-[#d8e3f2] text-xs text-[#786c85] flex items-center justify-between">
                <span>Contained PIDs:</span>
                <span className="font-mono text-[#3d5c85]">
                  {comparisonData.random_forest.contained_pids.length > 0
                    ? comparisonData.random_forest.contained_pids.join(', ')
                    : 'None'}
                </span>
              </div>
            </div>
          )}

          {/* XGBoost Card */}
          {comparisonData.xgboost && (
            <div className="rounded-xl bg-white/85 border border-[#ebdbe8] shadow-sm p-5 space-y-4 hover:border-[#d4c4d8] transition-all relative overflow-hidden">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Sparkles className="w-4 h-4 text-[#9d7394]" />
                  <h3 className="font-semibold text-[#2c2436] text-sm">XGBoost Classifier</h3>
                </div>
                {getDetectorBadge('xgboost')}
              </div>

              <div className="grid grid-cols-2 gap-3 pt-1">
                <div className="p-3 rounded-lg bg-[#faf6f9] border border-[#ebdbe8]">
                  <div className="flex items-center space-x-1.5 text-xs text-[#786c85] mb-1">
                    <Clock className="w-3 h-3 text-[#d49e35]" />
                    <span>Time to Detect</span>
                  </div>
                  <div className="text-lg font-bold font-mono text-[#2c2436]">
                    {comparisonData.xgboost.time_to_detect_seconds !== null
                      ? `${comparisonData.xgboost.time_to_detect_seconds.toFixed(1)}s`
                      : 'None'}
                  </div>
                  <div className="text-[11px] text-[#8c7f99]">
                    {comparisonData.xgboost.time_to_detect_windows !== null
                      ? `window #${comparisonData.xgboost.time_to_detect_windows}`
                      : 'Not triggered'}
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-[#faf6f9] border border-[#ebdbe8]">
                  <div className="flex items-center space-x-1.5 text-xs text-[#786c85] mb-1">
                    <AlertTriangle className="w-3 h-3 text-[#b54a5f]" />
                    <span>Files Lost</span>
                  </div>
                  <div className={`text-lg font-bold font-mono ${comparisonData.xgboost.files_lost > 0 ? 'text-[#9e3146]' : 'text-[#246e40]'}`}>
                    {comparisonData.xgboost.files_lost}
                  </div>
                  <div className="text-[11px] text-[#8c7f99]">
                    {comparisonData.xgboost.files_restored} restored via rollback
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-[#faf6f9] border border-[#ebdbe8]">
                  <div className="flex items-center space-x-1.5 text-xs text-[#786c85] mb-1">
                    <ShieldAlert className="w-3 h-3 text-[#d49e35]" />
                    <span>False Alarms</span>
                  </div>
                  <div className={`text-lg font-bold font-mono ${comparisonData.xgboost.false_alarms > 0 ? 'text-[#9b5825]' : 'text-[#246e40]'}`}>
                    {comparisonData.xgboost.false_alarms}
                  </div>
                  <div className="text-[11px] text-[#8c7f99]">Benign contained</div>
                </div>

                <div className="p-3 rounded-lg bg-[#faf6f9] border border-[#ebdbe8]">
                  <div className="flex items-center space-x-1.5 text-xs text-[#786c85] mb-1">
                    <FileCheck2 className="w-3 h-3 text-[#246e40]" />
                    <span>Files Preserved</span>
                  </div>
                  <div className="text-lg font-bold font-mono text-[#246e40]">
                    {comparisonData.xgboost.files_saved}
                  </div>
                  <div className="text-[11px] text-[#8c7f99]">Intact + recovered</div>
                </div>
              </div>

              <div className="pt-2 border-t border-[#ebdbe8] text-xs text-[#786c85] flex items-center justify-between">
                <span>Contained PIDs:</span>
                <span className="font-mono text-[#9d7394]">
                  {comparisonData.xgboost.contained_pids.length > 0
                    ? comparisonData.xgboost.contained_pids.join(', ')
                    : 'None'}
                </span>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Comparison Charts */}
      {chartData.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Chart 1: Detection Latency */}
          <div className="p-5 rounded-xl bg-white/85 border border-[#e5dbe8] shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <BarChart3 className="w-4 h-4 text-[#5b82a6]" />
                <h3 className="font-semibold text-[#2c2436] text-sm">Detection Latency (Seconds)</h3>
              </div>
              <span className="text-xs text-[#786c85]">Lower is better</span>
            </div>

            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} margin={{ top: 10, right: 20, left: -10, bottom: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#ede4ef" />
                  <XAxis dataKey="name" stroke="#8c7f99" tick={{ fontSize: 11 }} interval={0} />
                  <YAxis stroke="#8c7f99" tick={{ fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2d5e6', borderRadius: '8px', color: '#2c2436' }}
                    labelStyle={{ color: '#786c85' }}
                  />
                  <Bar dataKey="detectionDelay" name="Delay (s)" fill="#5b82a6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Chart 2: Damage vs Recovery */}
          <div className="p-5 rounded-xl bg-white/85 border border-[#e5dbe8] shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-4 h-4 text-[#5b9e75]" />
                <h3 className="font-semibold text-[#2c2436] text-sm">File Damage vs Rollback Restored</h3>
              </div>
              <span className="text-xs text-[#786c85]">Damage: lower is better</span>
            </div>

            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} margin={{ top: 10, right: 20, left: -10, bottom: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#ede4ef" />
                  <XAxis dataKey="name" stroke="#8c7f99" tick={{ fontSize: 11 }} interval={0} />
                  <YAxis stroke="#8c7f99" tick={{ fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2d5e6', borderRadius: '8px', color: '#2c2436' }}
                    labelStyle={{ color: '#786c85' }}
                  />
                  <Legend wrapperStyle={{ fontSize: 12, paddingTop: 10 }} />
                  <Bar dataKey="filesLost" name="Files Encrypted/Lost" fill="#b54a5f" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="filesRestored" name="Files Restored" fill="#5b9e75" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* Comparison Metrics Table */}
      {comparisonData && (
        <div className="rounded-xl bg-white/85 border border-[#e5dbe8] shadow-sm overflow-hidden">
          <div className="p-4 border-b border-[#ebdbe8] flex items-center justify-between">
            <h3 className="font-semibold text-[#2c2436] text-sm">Detailed Benchmark Comparison Table</h3>
            <span className="text-xs text-[#786c85]">Fixed Seed: {seed}</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#f9f5f6] text-[#786c85] uppercase tracking-wider font-semibold border-b border-[#ebdbe8]">
                <tr>
                  <th className="py-3 px-4">Detector</th>
                  <th className="py-3 px-4">Architecture</th>
                  <th className="py-3 px-4">Time to Detect</th>
                  <th className="py-3 px-4">Files Lost</th>
                  <th className="py-3 px-4">Files Restored</th>
                  <th className="py-3 px-4">Preserved Total</th>
                  <th className="py-3 px-4">False Alarms</th>
                  <th className="py-3 px-4">Contained PIDs</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#ebdbe8] text-[#4a3f55]">
                {Object.entries(comparisonData).map(([key, item]) => (
                  <tr key={key} className="hover:bg-[#fcfaf8] transition-colors">
                    <td className="py-3.5 px-4 font-medium text-[#2c2436] capitalize">
                      {key.replace('_', ' ')}
                    </td>
                    <td className="py-3.5 px-4">{getDetectorBadge(key)}</td>
                    <td className="py-3.5 px-4 font-mono">
                      {item.time_to_detect_seconds !== null ? (
                        <span className="text-[#9b5825] font-semibold">{item.time_to_detect_seconds.toFixed(1)}s</span>
                      ) : (
                        <span className="text-[#8c7f99]">N/A</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 font-mono font-semibold">
                      <span className={item.files_lost > 0 ? 'text-[#9e3146]' : 'text-[#246e40]'}>
                        {item.files_lost}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[#246e40]">
                      {item.files_restored}
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[#2c2436]">
                      {item.files_saved}
                    </td>
                    <td className="py-3.5 px-4 font-mono">
                      <span className={item.false_alarms > 0 ? 'text-[#9b5825] font-bold' : 'text-[#786c85]'}>
                        {item.false_alarms}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[#4a3f55]">
                      {item.contained_pids.length > 0 ? item.contained_pids.join(', ') : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
