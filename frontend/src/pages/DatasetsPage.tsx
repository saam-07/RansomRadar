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
  ScatterChart,
  Scatter,
  ZAxis,
} from 'recharts';
import {
  Database,
  RefreshCw,
  Table,
  Sliders,
  FileText,
  Sparkles,
  Search,
} from 'lucide-react';
import { api } from '../api/client';

export const DatasetsPage: React.FC = () => {
  const [splitsData, setSplitsData] = useState<any>(null);
  const [selectedSplit, setSelectedSplit] = useState<string>('train');
  const [sampleRows, setSampleRows] = useState<any[]>([]);
  const [statsData, setStatsData] = useState<any>(null);
  const [datasetCard, setDatasetCard] = useState<string>('');
  const [selectedFeature, setSelectedFeature] = useState<string>('t1_mean_entropy');
  const [scatterX, setScatterX] = useState<string>('t1_mean_entropy');
  const [scatterY, setScatterY] = useState<string>('rename_rate');
  const [filterLabel, setFilterLabel] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [seed, setSeed] = useState<number>(42);
  const [isImbalanced, setIsImbalanced] = useState<boolean>(false);
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [genStatus, setGenStatus] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'distributions' | 'samples' | 'card'>('overview');

  // Load dataset overview and card on mount
  useEffect(() => {
    api.getDatasets().then((data) => {
      setSplitsData(data);
    }).catch(console.error);

    api.getDatasetCard().then((res) => {
      setDatasetCard(res.content);
    }).catch(console.error);
  }, []);

  // Load split-specific sample and stats when selectedSplit changes
  useEffect(() => {
    api.getDatasetStats(selectedSplit).then((res) => {
      setStatsData(res);
    }).catch(console.error);

    api.getDatasetSample(selectedSplit, 50).then((res) => {
      setSampleRows(res.rows || []);
    }).catch(console.error);
  }, [selectedSplit]);

  const handleGenerate = async () => {
    setIsGenerating(true);
    setGenStatus(null);
    try {
      const res: any = await api.generateDataset({ seed, imbalanced: isImbalanced });
      setGenStatus(res.message);
      // Refresh overview
      const data = await api.getDatasets();
      setSplitsData(data);
      const stats = await api.getDatasetStats(selectedSplit);
      setStatsData(stats);
      const sample = await api.getDatasetSample(selectedSplit, 50);
      setSampleRows(sample.rows || []);
    } catch (e: any) {
      setGenStatus(`Error: ${e.message}`);
    } finally {
      setIsGenerating(false);
    }
  };

  // Prepare class balance chart data
  const classDist = statsData?.class_distribution || {};
  const classChartData = [
    { name: 'Benign Workday', count: classDist.benign || 0, fill: '#5b9e75' },
    { name: 'Nightly Backup', count: classDist.backup || 0, fill: '#5b82a6' },
    { name: 'OLTP Database', count: classDist.oltp || 0, fill: '#9d7394' },
    { name: 'Ransomware Outbreak', count: classDist.ransomware || 0, fill: '#b54a5f' },
  ];

  // Prepare feature distribution comparison data
  const featureStats = statsData?.feature_statistics?.[selectedFeature] || {};
  const featureChartData = Object.entries(featureStats).map(([cls, stat]: [string, any]) => ({
    class: cls,
    mean: stat.mean,
    p50: stat.p50,
    min: stat.min,
    max: stat.max,
    std: stat.std,
  }));

  // Prepare 2D scatter data
  const scatterData = sampleRows.map((r) => ({
    x: r[scatterX] ?? 0,
    y: r[scatterY] ?? 0,
    label: r.label,
    pid: r.pid,
    scenario: r.scenario,
  }));

  const filteredSampleRows = sampleRows.filter((r) => {
    if (filterLabel !== 'all' && r.label !== filterLabel) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchPid = String(r.pid).includes(q);
      const matchScen = String(r.scenario || '').toLowerCase().includes(q);
      const matchRun = String(r.run_id || '').toLowerCase().includes(q);
      return matchPid || matchScen || matchRun;
    }
    return true;
  });

  const schemaDefinitions = [
    { col: 'mod_rate', type: 'float', role: 'Tier-0', desc: 'File modification rate (fanotify write events/sec)' },
    { col: 'rename_rate', type: 'float', role: 'Tier-0', desc: 'File rename rate (events/sec)' },
    { col: 'create_del_rate', type: 'float', role: 'Tier-0', desc: 'File creation and deletion rate (events/sec)' },
    { col: 'event_count', type: 'int', role: 'Tier-0', desc: 'Total raw filesystem events observed in 2s window' },
    { col: 'concentration_gini', type: 'float', role: 'Tier-0', desc: 'Gini coefficient measuring path entropy concentration' },
    { col: 't1_write_rate', type: 'float', role: 'Tier-1', desc: 'eBPF sys_write syscall invocation rate' },
    { col: 't1_mean_entropy', type: 'float', role: 'Tier-1', desc: 'Shannon byte entropy (0.0 - 8.0) of written payload buffers' },
    { col: 't1_entropy_std', type: 'float', role: 'Tier-1', desc: 'Standard deviation of buffer entropy across window' },
    { col: 't1_unlink_rate', type: 'float', role: 'Tier-1', desc: 'eBPF sys_unlink deletion syscall rate' },
    { col: 't1_rename_rate', type: 'float', role: 'Tier-1', desc: 'eBPF sys_rename syscall invocation rate' },
    { col: 't1_mean_write_size', type: 'float', role: 'Tier-1', desc: 'Average byte buffer length per write operation' },
  ];

  return (
    <div className="flex-1 p-6 space-y-6 overflow-y-auto">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-[#ebdbe8] pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl font-bold text-[#2c2436] flex items-center space-x-2">
              <Database className="w-5 h-5 text-[#b56576]" />
              <span>Event Explorer</span>
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#eddce5] text-[#9d7394] border border-[#dcbcd1]">
              Benchmark Datasets Explorer
            </span>
          </div>
          <p className="text-xs text-[#786c85] mt-0.5">
            Explore 11-feature behavioral traces, class balance overlaps, schema contracts, and generate new benchmark datasets.
          </p>
        </div>

        {/* Tab Selector */}
        <div className="flex items-center space-x-1 bg-[#f2e9f2] p-1 rounded-xl border border-[#e0d3e5] text-xs font-mono">
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-3 py-1.5 rounded-lg transition-all ${activeTab === 'overview' ? 'bg-[#b56576] text-white font-bold shadow-sm' : 'text-[#6b5f77] hover:text-[#2c2436]'}`}
          >
            Overview & Splits
          </button>
          <button
            onClick={() => setActiveTab('distributions')}
            className={`px-3 py-1.5 rounded-lg transition-all ${activeTab === 'distributions' ? 'bg-[#b56576] text-white font-bold shadow-sm' : 'text-[#6b5f77] hover:text-[#2c2436]'}`}
          >
            Feature Distributions
          </button>
          <button
            onClick={() => setActiveTab('samples')}
            className={`px-3 py-1.5 rounded-lg transition-all ${activeTab === 'samples' ? 'bg-[#b56576] text-white font-bold shadow-sm' : 'text-[#6b5f77] hover:text-[#2c2436]'}`}
          >
            Trace Samples
          </button>
          <button
            onClick={() => setActiveTab('card')}
            className={`px-3 py-1.5 rounded-lg transition-all ${activeTab === 'card' ? 'bg-[#b56576] text-white font-bold shadow-sm' : 'text-[#6b5f77] hover:text-[#2c2436]'}`}
          >
            Dataset Card
          </button>
        </div>
      </div>

      {/* Split Selector Strip */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl bg-white/85 border border-[#e5dbe8] shadow-sm">
        <div className="flex items-center space-x-2 text-xs font-mono">
          <span className="text-[#786c85] font-medium">Active Split:</span>
          {['train', 'val', 'test', 'hard_test'].map((sp) => (
            <button
              key={sp}
              onClick={() => setSelectedSplit(sp)}
              className={`px-3 py-1.5 rounded-lg border transition-all ${
                selectedSplit === sp
                  ? 'bg-[#eddce5] text-[#b56576] border-[#dcbcd1] font-bold'
                  : 'bg-[#fcfaf8] text-[#786c85] border-[#ebdbe8] hover:text-[#2c2436]'
              }`}
            >
              {sp.toUpperCase()}
              {splitsData?.files?.[sp] && ` (${splitsData.files[sp].rows} rows)`}
            </button>
          ))}
        </div>

        <div className="flex items-center space-x-4 text-xs font-mono text-[#786c85]">
          <div>
            <span>Schema: </span>
            <strong className="text-[#2c2436]">v{splitsData?.schema_version || '1.0.0'}</strong>
          </div>
          <div>
            <span>Generator: </span>
            <strong className="text-[#2c2436]">v{splitsData?.generator_version || '1.0.0'}</strong>
          </div>
          <div>
            <span>Source Mix: </span>
            <span className="text-[#9b5825] font-bold">100% Synthetic</span>
          </div>
        </div>
      </div>

      {/* TAB 1: OVERVIEW & SPLITS */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Class Balance & Generation Form */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Class Balance Chart */}
            <div className="lg:col-span-2 p-5 rounded-xl bg-white/85 border border-[#e5dbe8] shadow-sm space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold uppercase tracking-wider text-[#2c2436]">
                  Class Distribution ({selectedSplit.toUpperCase()})
                </h3>
                <span className="text-xs font-mono text-[#786c85]">
                  Total: {statsData?.total_rows || 0} windows
                </span>
              </div>
              <div className="h-60 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={classChartData} margin={{ top: 10, right: 20, left: -10, bottom: 20 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#ede4ef" />
                    <XAxis dataKey="name" stroke="#8c7f99" tick={{ fontSize: 11 }} />
                    <YAxis stroke="#8c7f99" tick={{ fontSize: 11 }} />
                    <Tooltip contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2d5e6', borderRadius: '8px', color: '#2c2436' }} />
                    <Bar dataKey="count" name="Window Count" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Generate New Dataset Widget */}
            <div className="p-5 rounded-xl bg-white/85 border border-[#e5dbe8] shadow-sm space-y-4 flex flex-col justify-between">
              <div>
                <h3 className="text-sm font-semibold uppercase tracking-wider text-[#2c2436] flex items-center space-x-2">
                  <Sparkles className="w-4 h-4 text-[#9d7394]" />
                  <span>Regenerate Datasets</span>
                </h3>
                <p className="text-xs text-[#786c85] mt-1">
                  Re-runs synthetic traces generator with reproducible pseudo-random seed.
                </p>

                <div className="space-y-3 mt-4 text-xs font-mono">
                  <div>
                    <label className="text-[#786c85] block mb-1">Random Seed:</label>
                    <input
                      type="number"
                      value={seed}
                      onChange={(e) => setSeed(parseInt(e.target.value) || 42)}
                      className="w-full bg-[#fcfaf8] border border-[#d8c8dc] rounded-lg px-3 py-1.5 text-[#2c2436] focus:outline-none focus:border-[#b56576]"
                    />
                  </div>

                  <div className="flex items-center space-x-2 pt-1">
                    <input
                      type="checkbox"
                      id="imbalanced"
                      checked={isImbalanced}
                      onChange={(e) => setIsImbalanced(e.target.checked)}
                      className="rounded bg-white border-[#d8c8dc] text-[#b56576] accent-[#b56576]"
                    />
                    <label htmlFor="imbalanced" className="text-[#4a3f55]">
                      Imbalanced Mode (99.9% Benign)
                    </label>
                  </div>
                </div>
              </div>

              <div>
                {genStatus && (
                  <div className="p-2.5 rounded-lg bg-[#e5f5ec] border border-[#c0e6cf] text-[11px] font-mono text-[#246e40] mb-3">
                    {genStatus}
                  </div>
                )}
                <button
                  onClick={handleGenerate}
                  disabled={isGenerating}
                  className="w-full py-2.5 rounded-xl bg-[#b56576] hover:bg-[#a25364] disabled:opacity-50 text-white font-semibold text-xs flex items-center justify-center space-x-2 shadow-sm transition-all"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isGenerating ? 'animate-spin' : ''}`} />
                  <span>{isGenerating ? 'Generating Traces...' : 'Generate Datasets'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Schema Specification Table */}
          <div className="rounded-xl bg-white/85 border border-[#e5dbe8] shadow-sm overflow-hidden">
            <div className="p-4 border-b border-[#ebdbe8] flex items-center justify-between">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-[#2c2436] flex items-center space-x-2">
                <Table className="w-4 h-4 text-[#5b9e75]" />
                <span>Feature Schema Specification (11 Features)</span>
              </h3>
              <span className="text-xs font-mono text-[#786c85]">Strict Contract v1.0.0</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#f9f5f6] text-[#786c85] uppercase tracking-wider border-b border-[#ebdbe8]">
                  <tr>
                    <th className="py-2.5 px-4">Feature Name</th>
                    <th className="py-2.5 px-4">Tier</th>
                    <th className="py-2.5 px-4">Data Type</th>
                    <th className="py-2.5 px-4">Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#ebdbe8] text-[#4a3f55]">
                  {schemaDefinitions.map((item) => (
                    <tr key={item.col} className="hover:bg-[#fcfaf8]">
                      <td className="py-2 px-4 font-bold text-[#2c2436]">{item.col}</td>
                      <td className="py-2 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${item.role === 'Tier-0' ? 'bg-[#fdf7e7] text-[#87651a] border border-[#fae6b2]' : 'bg-[#eaf0f8] text-[#3d5c85] border border-[#c8d8ec]'}`}>
                          {item.role}
                        </span>
                      </td>
                      <td className="py-2 px-4 text-[#786c85]">{item.type}</td>
                      <td className="py-2 px-4 text-[#4a3f55] font-sans">{item.desc}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: FEATURE DISTRIBUTIONS */}
      {activeTab === 'distributions' && (
        <div className="space-y-6">
          <div className="p-4 rounded-xl bg-white/85 border border-[#e5dbe8] shadow-sm flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center space-x-2">
              <Sliders className="w-4 h-4 text-[#b56576]" />
              <label className="text-xs font-mono text-[#4a3f55]">Select Feature:</label>
              <select
                value={selectedFeature}
                onChange={(e) => setSelectedFeature(e.target.value)}
                className="bg-[#fcfaf8] border border-[#d8c8dc] rounded-lg px-3 py-1.5 text-xs font-mono text-[#2c2436] focus:outline-none focus:border-[#b56576]"
              >
                {schemaDefinitions.map((f) => (
                  <option key={f.col} value={f.col}>
                    {f.col} ({f.role})
                  </option>
                ))}
              </select>
            </div>
            <div className="text-xs font-mono text-[#786c85]">
              Comparing statistics across benign, backup, oltp, and ransomware
            </div>
          </div>

          {/* Feature Distribution Overlap Chart */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="p-5 rounded-xl bg-white/85 border border-[#e5dbe8] shadow-sm space-y-4">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-[#2c2436]">
                Mean & Median (p50) by Class for {selectedFeature}
              </h3>
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={featureChartData} margin={{ top: 10, right: 20, left: -10, bottom: 20 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#ede4ef" />
                    <XAxis dataKey="class" stroke="#8c7f99" tick={{ fontSize: 11 }} />
                    <YAxis stroke="#8c7f99" tick={{ fontSize: 11 }} />
                    <Tooltip contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2d5e6', borderRadius: '8px', color: '#2c2436' }} />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                    <Bar dataKey="mean" name="Mean" fill="#5b82a6" radius={[4, 4, 0, 0]} />
                    <Bar dataKey="p50" name="Median (p50)" fill="#5b9e75" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Min / Max Range Chart */}
            <div className="p-5 rounded-xl bg-white/85 border border-[#e5dbe8] shadow-sm space-y-4">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-[#2c2436]">
                Min vs Max Range & Std Dev for {selectedFeature}
              </h3>
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={featureChartData} margin={{ top: 10, right: 20, left: -10, bottom: 20 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#ede4ef" />
                    <XAxis dataKey="class" stroke="#8c7f99" tick={{ fontSize: 11 }} />
                    <YAxis stroke="#8c7f99" tick={{ fontSize: 11 }} />
                    <Tooltip contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2d5e6', borderRadius: '8px', color: '#2c2436' }} />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                    <Bar dataKey="min" name="Min Value" fill="#8c7f99" radius={[4, 4, 0, 0]} />
                    <Bar dataKey="max" name="Max Value" fill="#b54a5f" radius={[4, 4, 0, 0]} />
                    <Bar dataKey="std" name="Std Dev" fill="#d49e35" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* 2D Projection Scatter */}
          <div className="p-5 rounded-xl bg-white/85 border border-[#e5dbe8] shadow-sm space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <h3 className="text-sm font-semibold uppercase tracking-wider text-[#2c2436]">
                  2D Feature Projection Scatter (Class Separation & Overlap)
                </h3>
                <p className="text-xs text-[#786c85] mt-0.5">
                  Visualizes realistic class overlap (e.g. high-throughput backup vs fast ransomware).
                </p>
              </div>
              <div className="flex items-center space-x-3 text-xs font-mono">
                <div className="flex items-center space-x-1.5">
                  <span className="text-[#786c85]">X-Axis:</span>
                  <select
                    value={scatterX}
                    onChange={(e) => setScatterX(e.target.value)}
                    className="bg-[#fcfaf8] border border-[#d8c8dc] rounded px-2 py-1 text-[#2c2436] focus:outline-none focus:border-[#b56576]"
                  >
                    {schemaDefinitions.map((f) => (
                      <option key={f.col} value={f.col}>{f.col}</option>
                    ))}
                  </select>
                </div>
                <div className="flex items-center space-x-1.5">
                  <span className="text-[#786c85]">Y-Axis:</span>
                  <select
                    value={scatterY}
                    onChange={(e) => setScatterY(e.target.value)}
                    className="bg-[#fcfaf8] border border-[#d8c8dc] rounded px-2 py-1 text-[#2c2436] focus:outline-none focus:border-[#b56576]"
                  >
                    {schemaDefinitions.map((f) => (
                      <option key={f.col} value={f.col}>{f.col}</option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <ScatterChart margin={{ top: 10, right: 20, left: -10, bottom: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#ede4ef" />
                  <XAxis dataKey="x" name={scatterX} stroke="#8c7f99" tick={{ fontSize: 11 }} />
                  <YAxis dataKey="y" name={scatterY} stroke="#8c7f99" tick={{ fontSize: 11 }} />
                  <ZAxis range={[30, 40]} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2d5e6', borderRadius: '8px', color: '#2c2436' }}
                    formatter={(val: any, name: string) => [val, name]}
                  />
                  <Scatter
                    name="Benign"
                    data={scatterData.filter((d) => d.label === 'benign')}
                    fill="#5b9e75"
                  />
                  <Scatter
                    name="Backup"
                    data={scatterData.filter((d) => d.label === 'backup')}
                    fill="#5b82a6"
                  />
                  <Scatter
                    name="OLTP"
                    data={scatterData.filter((d) => d.label === 'oltp')}
                    fill="#9d7394"
                  />
                  <Scatter
                    name="Ransomware"
                    data={scatterData.filter((d) => d.label === 'ransomware')}
                    fill="#b54a5f"
                  />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                </ScatterChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: TRACE SAMPLES */}
      {activeTab === 'samples' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-white/85 border border-[#e5dbe8] shadow-sm flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center space-x-3">
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-[#786c85]" />
                <input
                  type="text"
                  placeholder="Filter PID, scenario, or run..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="bg-[#fcfaf8] border border-[#d8c8dc] rounded-lg pl-8 pr-3 py-1.5 text-xs text-[#2c2436] placeholder-[#8c7f99] font-mono focus:outline-none focus:border-[#b56576] w-56"
                />
              </div>

              <div className="flex items-center space-x-1 text-xs font-mono">
                <span className="text-[#786c85] mr-1">Class:</span>
                {['all', 'benign', 'backup', 'oltp', 'ransomware'].map((l) => (
                  <button
                    key={l}
                    onClick={() => setFilterLabel(l)}
                    className={`px-2.5 py-1 rounded-lg border transition-all ${
                      filterLabel === l
                        ? 'bg-[#eddce5] text-[#b56576] border-[#dcbcd1] font-bold'
                        : 'bg-[#fcfaf8] text-[#786c85] border-[#ebdbe8] hover:text-[#2c2436]'
                    }`}
                  >
                    {l.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>

            <span className="text-xs font-mono text-[#786c85]">
              Showing {filteredSampleRows.length} sample traces
            </span>
          </div>

          <div className="rounded-xl bg-white/85 border border-[#e5dbe8] shadow-sm overflow-hidden">
            <div className="overflow-x-auto max-h-[500px]">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#f9f5f6] text-[#786c85] uppercase tracking-wider sticky top-0 border-b border-[#ebdbe8]">
                  <tr>
                    <th className="py-2.5 px-3">PID</th>
                    <th className="py-2.5 px-3">Scenario</th>
                    <th className="py-2.5 px-3">Label</th>
                    <th className="py-2.5 px-3">Window</th>
                    <th className="py-2.5 px-3">Events</th>
                    <th className="py-2.5 px-3">Mod Rate</th>
                    <th className="py-2.5 px-3">Rename Rate</th>
                    <th className="py-2.5 px-3">Gini</th>
                    <th className="py-2.5 px-3">T1 Entropy</th>
                    <th className="py-2.5 px-3">T1 Write Rate</th>
                    <th className="py-2.5 px-3">Source</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#ebdbe8] text-[#4a3f55]">
                  {filteredSampleRows.map((r, i) => (
                    <tr key={i} className="hover:bg-[#fcfaf8]">
                      <td className="py-2 px-3 text-[#2c2436] font-bold">{r.pid}</td>
                      <td className="py-2 px-3 text-[#786c85] truncate max-w-[120px]">{r.scenario}</td>
                      <td className="py-2 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          r.label === 'ransomware' ? 'bg-[#fdecee] text-[#9e3146] border border-[#f8c4cd]' :
                          r.label === 'backup' ? 'bg-[#eaf0f8] text-[#3d5c85] border border-[#c8d8ec]' :
                          r.label === 'oltp' ? 'bg-[#eddce5] text-[#9d7394] border border-[#dcbcd1]' :
                          'bg-[#e5f5ec] text-[#246e40] border border-[#c0e6cf]'
                        }`}>
                          {r.label}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-[#786c85]">{r.window_idx}</td>
                      <td className="py-2 px-3">{r.event_count}</td>
                      <td className="py-2 px-3">{r.mod_rate?.toFixed(2) ?? '—'}</td>
                      <td className="py-2 px-3">{r.rename_rate?.toFixed(2) ?? '—'}</td>
                      <td className="py-2 px-3">{r.concentration_gini?.toFixed(3) ?? '—'}</td>
                      <td className="py-2 px-3 font-semibold text-[#9b5825]">
                        {r.t1_mean_entropy !== null && r.t1_mean_entropy !== undefined ? r.t1_mean_entropy.toFixed(3) : 'NaN (Tier-0)'}
                      </td>
                      <td className="py-2 px-3">
                        {r.t1_write_rate !== null && r.t1_write_rate !== undefined ? r.t1_write_rate.toFixed(2) : 'NaN'}
                      </td>
                      <td className="py-2 px-3 text-[#8c7f99]">{r.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: DATASET CARD */}
      {activeTab === 'card' && (
        <div className="p-6 rounded-xl bg-white/85 border border-[#e5dbe8] shadow-sm space-y-4">
          <div className="flex items-center space-x-2 border-b border-[#ebdbe8] pb-3">
            <FileText className="w-5 h-5 text-[#b56576]" />
            <h3 className="text-sm font-semibold uppercase tracking-wider text-[#2c2436]">
              Rendered Dataset Card (`data/DATASET_CARD.md`)
            </h3>
          </div>
          <pre className="text-xs font-mono text-[#2c2436] bg-[#fcfaf8] p-4 rounded-xl border border-[#ebdbe8] overflow-x-auto whitespace-pre-wrap leading-relaxed">
            {datasetCard || 'Loading dataset card...'}
          </pre>
        </div>
      )}
    </div>
  );
};
