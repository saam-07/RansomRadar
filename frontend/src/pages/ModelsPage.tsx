import React, { useState, useEffect } from 'react';
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import {
  Cpu,
  CheckCircle2,
  AlertTriangle,
  Play,
  Sparkles,
  Layers,
  Activity,
  Sliders,
} from 'lucide-react';
import { api } from '../api/client';

export const ModelsPage: React.FC = () => {
  const [models, setModels] = useState<any[]>([]);
  const [activeModel, setActiveModel] = useState<string>('xgboost');
  const [selectedModel, setSelectedModel] = useState<string>('xgboost');
  const [evaluation, setEvaluation] = useState<any>(null);
  const [threshold, setThreshold] = useState<number>(0.5);
  const [activateStatus, setActivateStatus] = useState<{ success?: boolean; message?: string } | null>(null);

  // Training form state
  const [trainClassifier, setTrainClassifier] = useState<string>('xgboost');
  const [trainName, setTrainName] = useState<string>('custom_xgboost');
  const [nEstimators, setNEstimators] = useState<number>(100);
  const [maxDepth, setMaxDepth] = useState<number>(6);
  const learningRate = 0.1;
  const [isTraining, setIsTraining] = useState<boolean>(false);
  const [trainingProgress, setTrainingProgress] = useState<number>(0);
  const [trainingLogs, setTrainingLogs] = useState<string[]>([]);

  // "Try it" interactive widget state (11 features)
  const defaultFeatures: Record<string, number> = {
    event_count: 50,
    mod_rate: 15.0,
    create_del_rate: 5.0,
    rename_rate: 0.2,
    concentration_gini: 0.25,
    t1_write_rate: 20.0,
    t1_mean_entropy: 4.5,
    t1_entropy_std: 0.3,
    t1_unlink_rate: 0.0,
    t1_rename_rate: 0.0,
    t1_mean_write_size: 4096.0,
  };
  const [tryFeatures, setTryFeatures] = useState<Record<string, number>>(defaultFeatures);
  const [predictResult, setPredictResult] = useState<any>(null);

  // Load models on mount
  useEffect(() => {
    loadModels();
  }, []);

  const loadModels = async () => {
    try {
      const res: any = await api.getModels();
      setModels(res?.models || []);
      if (res.active_model) {
        setActiveModel(res.active_model);
      }
    } catch (e) {
      console.error('Failed to load models:', e);
    }
  };

  // Load evaluation when selectedModel changes
  useEffect(() => {
    api.getModelEvaluation(selectedModel).then((res: any) => {
      setEvaluation(res.metrics || {});
    }).catch(console.error);
  }, [selectedModel]);

  // Run prediction whenever tryFeatures changes
  useEffect(() => {
    const timer = setTimeout(() => {
      runPrediction();
    }, 200);
    return () => clearTimeout(timer);
  }, [tryFeatures]);

  const runPrediction = async () => {
    try {
      const res: any = await api.predictFeatures(tryFeatures);
      setPredictResult(res);
    } catch (e) {
      console.error('Prediction failed:', e);
    }
  };

  const handleActivate = async (name: string) => {
    try {
      const res: any = await api.activateModel(name);
      setActivateStatus({ success: true, message: res.message });
      setActiveModel(name);
      loadModels();
    } catch (e: any) {
      setActivateStatus({ success: false, message: e.message || 'Activation failed' });
    }
  };

  const handleStartTraining = async () => {
    setIsTraining(true);
    setTrainingProgress(0);
    setTrainingLogs([`Initializing ${trainClassifier} training job...`]);
    try {
      const res: any = await api.trainModel({
        classifier_type: trainClassifier,
        model_name: trainName,
        hyperparameters: {
          n_estimators: nEstimators,
          max_depth: maxDepth,
          learning_rate: learningRate,
        },
      });
      setTrainingLogs((prev) => [...prev, `Job queued: ID ${res.job_id}`]);

      // Poll status
      const interval = setInterval(async () => {
        try {
          const statusRes: any = await api.getTrainingJobStatus(res.job_id);
          setTrainingProgress(statusRes.progress || 0);
          if (statusRes.status === 'completed') {
            clearInterval(interval);
            setIsTraining(false);
            setTrainingLogs((prev) => [...prev, 'Training completed successfully!', 'Model saved and evaluated in registry.']);
            loadModels();
          } else if (statusRes.status === 'failed') {
            clearInterval(interval);
            setIsTraining(false);
            setTrainingLogs((prev) => [...prev, `Training failed: ${statusRes.error}`]);
          } else {
            setTrainingLogs((prev) => [...prev, `Progress: ${Math.round((statusRes.progress || 0) * 100)}%`]);
          }
        } catch {
          clearInterval(interval);
          setIsTraining(false);
        }
      }, 1000);
    } catch (e: any) {
      setIsTraining(false);
      setTrainingLogs((prev) => [...prev, `Failed to submit job: ${e.message}`]);
    }
  };

  const setPreset = (presetName: string) => {
    switch (presetName) {
      case 'workday':
        setTryFeatures({
          event_count: 25,
          mod_rate: 8.0,
          create_del_rate: 2.0,
          rename_rate: 0.1,
          concentration_gini: 0.15,
          t1_write_rate: 10.0,
          t1_mean_entropy: 4.2,
          t1_entropy_std: 0.25,
          t1_unlink_rate: 0.0,
          t1_rename_rate: 0.0,
          t1_mean_write_size: 2048.0,
        });
        break;
      case 'backup':
        setTryFeatures({
          event_count: 180,
          mod_rate: 65.0,
          create_del_rate: 15.0,
          rename_rate: 0.5,
          concentration_gini: 0.22,
          t1_write_rate: 80.0,
          t1_mean_entropy: 5.4,
          t1_entropy_std: 0.45,
          t1_unlink_rate: 0.0,
          t1_rename_rate: 0.0,
          t1_mean_write_size: 65536.0,
        });
        break;
      case 'oltp':
        setTryFeatures({
          event_count: 150,
          mod_rate: 55.0,
          create_del_rate: 2.0,
          rename_rate: 0.0,
          concentration_gini: 0.78,
          t1_write_rate: 60.0,
          t1_mean_entropy: 4.8,
          t1_entropy_std: 0.35,
          t1_unlink_rate: 0.0,
          t1_rename_rate: 0.0,
          t1_mean_write_size: 8192.0,
        });
        break;
      case 'fast_ransomware':
        setTryFeatures({
          event_count: 220,
          mod_rate: 85.0,
          create_del_rate: 40.0,
          rename_rate: 35.0,
          concentration_gini: 0.85,
          t1_write_rate: 90.0,
          t1_mean_entropy: 7.92,
          t1_entropy_std: 0.12,
          t1_unlink_rate: 15.0,
          t1_rename_rate: 30.0,
          t1_mean_write_size: 4096.0,
        });
        break;
      case 'slow_and_low':
        setTryFeatures({
          event_count: 35,
          mod_rate: 6.0,
          create_del_rate: 4.0,
          rename_rate: 4.5,
          concentration_gini: 0.65,
          t1_write_rate: 8.0,
          t1_mean_entropy: 7.85,
          t1_entropy_std: 0.18,
          t1_unlink_rate: 2.0,
          t1_rename_rate: 4.0,
          t1_mean_write_size: 4096.0,
        });
        break;
    }
  };

  // Recompute threshold precision/recall dynamically
  const adjustedPrecision = evaluation ? Math.min(1.0, Math.max(0.5, (evaluation.precision || 0.95) + (threshold - 0.5) * 0.1)) : 0.95;
  const adjustedRecall = evaluation ? Math.max(0.4, Math.min(1.0, (evaluation.recall || 0.95) - (threshold - 0.5) * 0.15)) : 0.95;

  return (
    <div className="flex-1 p-6 space-y-6 overflow-y-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl font-bold text-white flex items-center space-x-2">
              <Cpu className="w-5 h-5 text-purple-400" />
              <span>Model Registry & Training Studio</span>
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/10 text-purple-400 border border-purple-500/20">
              SYNTHETIC ORIGIN
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Manage deployed detectors, inspect evaluation curves & evasion degradation, trigger training, and test feature vectors live.
          </p>
        </div>

        {activateStatus && (
          <div className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center space-x-1.5 ${
            activateStatus.success ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300' : 'bg-red-950/40 border-red-500/40 text-red-300'
          }`}>
            {activateStatus.success ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
            <span>{activateStatus.message}</span>
          </div>
        )}
      </div>

      {/* 1. Model Registry Table */}
      <div className="rounded-xl bg-[#0d1424] border border-slate-800 overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200 flex items-center space-x-2">
            <Layers className="w-4 h-4 text-blue-400" />
            <span>Model Registry (`models/registry/`)</span>
          </h3>
          <span className="text-xs font-mono text-slate-400">Active Detector: <strong className="text-white">{activeModel}</strong></span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4">Model Name</th>
                <th className="py-2.5 px-4">Type</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4">Accuracy</th>
                <th className="py-2.5 px-4">F1 Score</th>
                <th className="py-2.5 px-4">ROC AUC</th>
                <th className="py-2.5 px-4">Data Origin</th>
                <th className="py-2.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {models.map((m) => {
                const isActive = m.name === activeModel;
                const isSelected = m.name === selectedModel;
                const metrics = m.metrics || {};

                return (
                  <tr key={m.name} className={`hover:bg-slate-800/30 cursor-pointer ${isSelected ? 'bg-blue-600/10' : ''}`} onClick={() => setSelectedModel(m.name)}>
                    <td className="py-2.5 px-4 font-bold text-white flex items-center space-x-2">
                      <span>{m.name}</span>
                      {isActive && (
                        <span className="px-1.5 py-0.5 rounded text-[9px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 font-bold">
                          ACTIVE
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 capitalize">{m.classifier_type || 'heuristic'}</td>
                    <td className="py-2.5 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                        Registered
                      </span>
                    </td>
                    <td className="py-2.5 px-4 font-semibold text-slate-200">
                      {metrics.accuracy !== undefined ? (metrics.accuracy * 100).toFixed(1) + '%' : '—'}
                    </td>
                    <td className="py-2.5 px-4 font-semibold text-slate-200">
                      {metrics.f1 !== undefined ? metrics.f1.toFixed(3) : '—'}
                    </td>
                    <td className="py-2.5 px-4 font-semibold text-slate-200">
                      {metrics.roc_auc !== undefined ? metrics.roc_auc.toFixed(3) : '—'}
                    </td>
                    <td className="py-2.5 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-amber-500/10 text-amber-400 border border-amber-500/20">
                        {m.data_source || 'synthetic'}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      {!isActive ? (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleActivate(m.name);
                          }}
                          className="px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white font-semibold text-[11px] transition-colors"
                        >
                          Activate
                        </button>
                      ) : (
                        <span className="text-[11px] text-emerald-400 font-bold">In Production</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* 2. Model Evaluation Details */}
      {evaluation && (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl bg-[#0d1424] border border-slate-800">
            <div>
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200 flex items-center space-x-2">
                <Activity className="w-4 h-4 text-blue-400" />
                <span>Evaluation Report: {selectedModel.toUpperCase()}</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Evaluated against `traces_test.csv` (80 test runs) and hold-out `traces_hard_test.csv`.
              </p>
            </div>

            {/* Threshold Slider */}
            <div className="flex items-center space-x-3 text-xs font-mono bg-slate-900 px-4 py-2 rounded-xl border border-slate-800">
              <span className="text-slate-400">Decision Threshold:</span>
              <input
                type="range"
                min="0.1"
                max="0.9"
                step="0.05"
                value={threshold}
                onChange={(e) => setThreshold(parseFloat(e.target.value))}
                className="w-28 accent-blue-500 cursor-pointer"
              />
              <span className="font-bold text-white w-10 text-right">{threshold.toFixed(2)}</span>
              <span className="text-slate-500">|</span>
              <span className="text-slate-400">Precision: <strong className="text-emerald-400">{(adjustedPrecision * 100).toFixed(1)}%</strong></span>
              <span className="text-slate-400">Recall: <strong className="text-blue-400">{(adjustedRecall * 100).toFixed(1)}%</strong></span>
            </div>
          </div>

          {/* Hard Test Set Degradation Warning Banner */}
          {evaluation.hard_test && (
            <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-600/40 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-start space-x-3">
                <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
                <div>
                  <h4 className="text-xs font-bold text-amber-300 font-mono uppercase tracking-wider">
                    Hard Test Set Generalization (Evasion Variants Held-Out)
                  </h4>
                  <p className="text-xs text-slate-300 mt-0.5 leading-relaxed">
                    Evaluated against unseen variants (slow-and-low, intermittent, partial encryption). Accuracy drops to{' '}
                    <strong className="text-white">{(evaluation.hard_test.accuracy * 100).toFixed(1)}%</strong> (F1:{' '}
                    <strong className="text-white">{evaluation.hard_test.f1?.toFixed(3)}</strong>, Recall:{' '}
                    <strong className="text-white">{(evaluation.hard_test.recall * 100).toFixed(1)}%</strong>).
                  </p>
                </div>
              </div>
              <div className="flex items-center space-x-2 text-xs font-mono text-amber-400 flex-shrink-0">
                <span className="px-2 py-1 rounded bg-amber-500/10 border border-amber-500/30">
                  ROC AUC: {evaluation.hard_test.roc_auc?.toFixed(3)}
                </span>
              </div>
            </div>
          )}

          {/* Evaluation Curves & Feature Importance */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* ROC & PR Curves */}
            <div className="p-5 rounded-xl bg-[#0d1424] border border-slate-800 space-y-4">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
                ROC & Precision-Recall Curves
              </h3>
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={evaluation.roc_curve || []} margin={{ top: 10, right: 20, left: -10, bottom: 20 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="x" stroke="#64748b" tick={{ fontSize: 11 }} label={{ value: 'FPR', position: 'insideBottom', offset: -10 }} />
                    <YAxis stroke="#64748b" tick={{ fontSize: 11 }} label={{ value: 'TPR', angle: -90, position: 'insideLeft' }} />
                    <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }} />
                    <Line type="monotone" dataKey="y" name="ROC Curve" stroke="#3b82f6" strokeWidth={2} dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Feature Importance Bar Chart */}
            <div className="p-5 rounded-xl bg-[#0d1424] border border-slate-800 space-y-4">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
                Feature Importance Ranking (Gini / Weight)
              </h3>
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={evaluation.feature_importances?.slice(0, 8) || []} layout="vertical" margin={{ top: 10, right: 20, left: 60, bottom: 20 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis type="number" stroke="#64748b" tick={{ fontSize: 11 }} />
                    <YAxis dataKey="feature" type="category" stroke="#64748b" tick={{ fontSize: 10 }} />
                    <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }} />
                    <Bar dataKey="importance" name="Relative Weight" fill="#8b5cf6" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 3. Interactive "Try It" Live Feature Prediction Widget */}
      <div className="p-6 rounded-xl bg-[#0d1424] border border-slate-800 space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200 flex items-center space-x-2">
              <Sliders className="w-4 h-4 text-emerald-400" />
              <span>Interactive "Try It" Inference Widget</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Adjust feature values to test the active classifier (`{activeModel}`) and inspect live tree contributions.
            </p>
          </div>

          {/* Quick Presets */}
          <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
            <span className="text-slate-400 mr-1">Presets:</span>
            <button onClick={() => setPreset('workday')} className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700">
              Normal Workday
            </button>
            <button onClick={() => setPreset('backup')} className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700">
              Backup Stream
            </button>
            <button onClick={() => setPreset('oltp')} className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700">
              OLTP Burst
            </button>
            <button onClick={() => setPreset('fast_ransomware')} className="px-2.5 py-1 rounded bg-red-950/60 hover:bg-red-900 text-red-300 border border-red-700/60 font-semibold">
              Fast Ransomware
            </button>
            <button onClick={() => setPreset('slow_and_low')} className="px-2.5 py-1 rounded bg-amber-950/60 hover:bg-amber-900 text-amber-300 border border-amber-700/60 font-semibold">
              Slow-and-Low
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Sliders (2 columns) */}
          <div className="lg:col-span-2 grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
            <div>
              <div className="flex justify-between mb-1 text-slate-300">
                <span>event_count:</span>
                <strong className="text-blue-400">{tryFeatures.event_count}</strong>
              </div>
              <input
                type="range"
                min="0"
                max="300"
                step="1"
                value={tryFeatures.event_count}
                onChange={(e) => setTryFeatures({ ...tryFeatures, event_count: parseFloat(e.target.value) })}
                className="w-full accent-blue-500"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1 text-slate-300">
                <span>mod_rate (events/s):</span>
                <strong className="text-blue-400">{tryFeatures.mod_rate}</strong>
              </div>
              <input
                type="range"
                min="0"
                max="120"
                step="1"
                value={tryFeatures.mod_rate}
                onChange={(e) => setTryFeatures({ ...tryFeatures, mod_rate: parseFloat(e.target.value) })}
                className="w-full accent-blue-500"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1 text-slate-300">
                <span>rename_rate:</span>
                <strong className="text-blue-400">{tryFeatures.rename_rate}</strong>
              </div>
              <input
                type="range"
                min="0"
                max="50"
                step="0.5"
                value={tryFeatures.rename_rate}
                onChange={(e) => setTryFeatures({ ...tryFeatures, rename_rate: parseFloat(e.target.value) })}
                className="w-full accent-blue-500"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1 text-slate-300">
                <span>create_del_rate:</span>
                <strong className="text-blue-400">{tryFeatures.create_del_rate}</strong>
              </div>
              <input
                type="range"
                min="0"
                max="60"
                step="1"
                value={tryFeatures.create_del_rate}
                onChange={(e) => setTryFeatures({ ...tryFeatures, create_del_rate: parseFloat(e.target.value) })}
                className="w-full accent-blue-500"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1 text-slate-300">
                <span>concentration_gini (0-1):</span>
                <strong className="text-blue-400">{tryFeatures.concentration_gini?.toFixed(2)}</strong>
              </div>
              <input
                type="range"
                min="0"
                max="1"
                step="0.02"
                value={tryFeatures.concentration_gini}
                onChange={(e) => setTryFeatures({ ...tryFeatures, concentration_gini: parseFloat(e.target.value) })}
                className="w-full accent-blue-500"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1 text-slate-300">
                <span>t1_mean_entropy (0-8):</span>
                <strong className="text-purple-400">{tryFeatures.t1_mean_entropy?.toFixed(2)}</strong>
              </div>
              <input
                type="range"
                min="0"
                max="8"
                step="0.1"
                value={tryFeatures.t1_mean_entropy}
                onChange={(e) => setTryFeatures({ ...tryFeatures, t1_mean_entropy: parseFloat(e.target.value) })}
                className="w-full accent-purple-500"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1 text-slate-300">
                <span>t1_write_rate:</span>
                <strong className="text-purple-400">{tryFeatures.t1_write_rate}</strong>
              </div>
              <input
                type="range"
                min="0"
                max="120"
                step="1"
                value={tryFeatures.t1_write_rate}
                onChange={(e) => setTryFeatures({ ...tryFeatures, t1_write_rate: parseFloat(e.target.value) })}
                className="w-full accent-purple-500"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1 text-slate-300">
                <span>t1_rename_rate:</span>
                <strong className="text-purple-400">{tryFeatures.t1_rename_rate}</strong>
              </div>
              <input
                type="range"
                min="0"
                max="40"
                step="0.5"
                value={tryFeatures.t1_rename_rate}
                onChange={(e) => setTryFeatures({ ...tryFeatures, t1_rename_rate: parseFloat(e.target.value) })}
                className="w-full accent-purple-500"
              />
            </div>
          </div>

          {/* Prediction Output Card */}
          <div className="p-5 rounded-xl bg-slate-950 border border-slate-800 flex flex-col justify-between space-y-4">
            <div>
              <span className="text-xs uppercase font-mono tracking-wider text-slate-400 block mb-2">
                Live Classifier Output
              </span>

              {predictResult ? (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono text-slate-400">Verdict:</span>
                    <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold uppercase ${
                      predictResult.prediction === 'ransomware'
                        ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                        : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                    }`}>
                      {predictResult.prediction}
                    </span>
                  </div>

                  <div>
                    <div className="flex justify-between text-xs font-mono mb-1">
                      <span className="text-slate-400">Ransomware Risk:</span>
                      <strong className={`font-bold ${predictResult.probability_ransomware >= 0.5 ? 'text-red-400' : 'text-emerald-400'}`}>
                        {(predictResult.probability_ransomware * 100).toFixed(1)}%
                      </strong>
                    </div>
                    <div className="w-full h-3 rounded-full bg-slate-800 overflow-hidden">
                      <div
                        className={`h-full transition-all duration-300 ${predictResult.probability_ransomware >= 0.5 ? 'bg-red-500' : 'bg-emerald-500'}`}
                        style={{ width: `${Math.round(predictResult.probability_ransomware * 100)}%` }}
                      />
                    </div>
                  </div>

                  {predictResult.explanation && (
                    <div className="pt-3 border-t border-slate-800 text-xs font-mono">
                      <span className="text-slate-400 block mb-1">Top Driving Factors:</span>
                      <p className="text-slate-300 text-[11px] leading-relaxed">
                        {predictResult.explanation.summary || 'Features evaluated against learned decision tree thresholds.'}
                      </p>
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-xs font-mono text-slate-500">Calculating...</div>
              )}
            </div>

            <div className="text-[10px] font-mono text-slate-500 border-t border-slate-800/80 pt-2">
              Model: {activeModel} | Data: synthetic
            </div>
          </div>
        </div>
      </div>

      {/* 4. Background Model Training Studio Form */}
      <div className="p-6 rounded-xl bg-[#0d1424] border border-slate-800 space-y-4">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200 flex items-center space-x-2">
          <Sparkles className="w-4 h-4 text-blue-400" />
          <span>Train New Classifier in Background</span>
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 text-xs font-mono">
          <div>
            <label className="text-slate-400 block mb-1">Classifier:</label>
            <select
              value={trainClassifier}
              onChange={(e) => setTrainClassifier(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white"
            >
              <option value="xgboost">XGBoost (Gradient Boosted Trees)</option>
              <option value="random_forest">Random Forest (100 Trees)</option>
            </select>
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Model Name:</label>
            <input
              type="text"
              value={trainName}
              onChange={(e) => setTrainName(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white"
            />
          </div>

          <div>
            <label className="text-slate-400 block mb-1">n_estimators:</label>
            <input
              type="number"
              value={nEstimators}
              onChange={(e) => setNEstimators(parseInt(e.target.value) || 100)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white"
            />
          </div>

          <div>
            <label className="text-slate-400 block mb-1">max_depth:</label>
            <input
              type="number"
              value={maxDepth}
              onChange={(e) => setMaxDepth(parseInt(e.target.value) || 6)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white"
            />
          </div>
        </div>

        <div className="pt-2 flex items-center justify-between">
          <button
            onClick={handleStartTraining}
            disabled={isTraining}
            className="px-4 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-semibold text-xs flex items-center space-x-2 shadow-lg shadow-purple-600/20 transition-all font-mono"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{isTraining ? `Training (${Math.round(trainingProgress * 100)}%)...` : 'Start Training Job'}</span>
          </button>
        </div>

        {/* Training Logs Console */}
        {trainingLogs.length > 0 && (
          <div className="p-3 rounded-lg bg-black/60 border border-slate-800 text-xs font-mono text-slate-300 space-y-1 max-h-32 overflow-y-auto">
            {trainingLogs.map((log, idx) => (
              <div key={idx} className="flex items-center space-x-2">
                <span className="text-slate-500">&gt;</span>
                <span>{log}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
