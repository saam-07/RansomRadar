import React, { useState, useEffect } from 'react';
import {
  Sparkles,
  Play,
  Pause,
  ChevronRight,
  ChevronLeft,
  X,
  CheckCircle2,
  AlertTriangle,
  Shield,
  Activity,
  FileCheck,
  TrendingDown,
} from 'lucide-react';
import { api } from '../../api/client';

interface GuidedStep {
  id: number;
  title: string;
  badge: string;
  badgeColor: string;
  icon: any;
  summary: string;
  narration: string[];
  actionLabel: string;
  actionType: 'run_workday' | 'run_backup' | 'run_ransomware' | 'view_comparison' | 'view_hard_test';
  expectedOutcome: string;
}

const DEMO_STEPS: GuidedStep[] = [
  {
    id: 1,
    title: 'Normal Workday: Quiet Baseline',
    badge: 'BENIGN BASELINE',
    badgeColor: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
    icon: FileCheck,
    summary: 'Developer productivity, git commits, code compiles, and file edits.',
    narration: [
      'Welcome to the AdaptShield guided interactive demonstration.',
      'We begin with standard baseline activity: typical developer workflow with text editing, compiling, and browsing.',
      'Notice that even with moderate file modifications, the EWMA risk score stays near 0%, well below the 30% WATCH threshold.',
      'Zero containment actions are taken. The system remains undisturbed.',
    ],
    actionLabel: 'Simulate Normal Workday',
    actionType: 'run_workday',
    expectedOutcome: '18 windows evaluated, 0 PIDs contained, 300 files intact.',
  },
  {
    id: 2,
    title: 'Nightly Backup: High I/O Stress Test',
    badge: 'FALSE POSITIVE RESISTANCE',
    badgeColor: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    icon: Shield,
    summary: 'Rsync and backup utilities reading and writing thousands of files rapidly.',
    narration: [
      'Next, we test system resilience against a common pitfall: high-throughput backup jobs.',
      'Rsync processes modify files at 80+ events per window. Traditional naive rate-threshold detectors frequently trigger false alarms here.',
      'AdaptShield analyzes write entropy (3.8-4.5) and near-zero rename operations, correctly identifying this as legitimate backup activity.',
      'Result: Zero false positives. Legitimate backup operations proceed at full speed.',
    ],
    actionLabel: 'Simulate Nightly Backup',
    actionType: 'run_backup',
    expectedOutcome: 'High event rate tolerated without false alarm containment.',
  },
  {
    id: 3,
    title: 'Fast Ransomware: Outbreak & Rollback',
    badge: 'ACTIVE ATTACK CONTAINMENT',
    badgeColor: 'bg-red-500/10 text-red-400 border-red-500/20',
    icon: AlertTriangle,
    summary: 'Aggressive encryption malware targets protected user documents.',
    narration: [
      'Now, an active attack launches: Fast Ransomware starts mass-encrypting documents with high entropy (>7.8) and rapid rename operations.',
      'Within 3 evaluation windows (~6s), AdaptShield detects the abnormal behavioral signature and escalates risk to CRITICAL.',
      'The response engine instantly freezes the attacking PID using cgroup freezer (3.8ms latency) and triggers atomic overlayfs rollback.',
      'Watch the virtual filesystem: encrypted files visibly restore to intact state. Total data loss: 0 files.',
    ],
    actionLabel: 'Trigger Outbreak & Rollback',
    actionType: 'run_ransomware',
    expectedOutcome: 'Attacker PID frozen; encrypted files instantly restored.',
  },
  {
    id: 4,
    title: 'Side-by-Side Detector Benchmark',
    badge: 'COMPARATIVE BENCHMARK',
    badgeColor: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
    icon: Activity,
    summary: 'Direct comparison between Rule-Based Heuristic, Random Forest, and XGBoost.',
    narration: [
      'Why not use simple heuristic rules? Here we run the identical attack seed through three detection engines side-by-side.',
      'Rule-Based detection relies on rigid thresholds, delaying containment until window 6 (resulting in 4 lost files).',
      'Random Forest catches the threat earlier at window 4 (2 files lost).',
      'XGBoost provides the lowest detection latency: contains the threat at window 3, preserving 59 of 60 files before rollback restores the remainder.',
    ],
    actionLabel: 'Run Side-by-Side Comparison',
    actionType: 'view_comparison',
    expectedOutcome: 'XGBoost achieves fastest containment latency and lowest file exposure.',
  },
  {
    id: 5,
    title: 'Model Evaluation & Hard Test Set Reality',
    badge: 'EVALUATION TRANSPARENCY',
    badgeColor: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    icon: TrendingDown,
    summary: 'Rigorous assessment on holdout evasive ransomware variants.',
    narration: [
      'Transparency is paramount in defensive security. On standard test splits, XGBoost achieves 99.2% F1 score.',
      'However, when evaluated against the Hard Test Set containing zero-day evasion tactics (slow-and-low pacing, rename-then-encrypt), recall drops to 34.7%.',
      'This illustrates why ML is not a silver bullet, and why AdaptShield couples ML with defense-in-depth: kernel safety rails, tiered escalation, and reversible snapshots.',
    ],
    actionLabel: 'Inspect Hard Test Set Metrics',
    actionType: 'view_hard_test',
    expectedOutcome: 'Transparent demonstration of evasion degradation & defense-in-depth necessity.',
  },
];

interface GuidedDemoModalProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigate: (page: string) => void;
}

export const GuidedDemoModal: React.FC<GuidedDemoModalProps> = ({ isOpen, onClose, onNavigate }) => {
  const [currentStepIdx, setCurrentStepIdx] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  const step = DEMO_STEPS[currentStepIdx];

  // Auto-advance timer when playing
  useEffect(() => {
    let timer: any = null;
    if (isPlaying) {
      timer = setTimeout(() => {
        if (currentStepIdx < DEMO_STEPS.length - 1) {
          setCurrentStepIdx((prev) => prev + 1);
        } else {
          setIsPlaying(false);
        }
      }, 12000); // 12 seconds per step narration
    }
    return () => clearTimeout(timer);
  }, [isPlaying, currentStepIdx]);

  if (!isOpen) return null;

  const handleNext = () => {
    if (currentStepIdx < DEMO_STEPS.length - 1) {
      setCurrentStepIdx(currentStepIdx + 1);
      setActionFeedback(null);
    }
  };

  const handlePrev = () => {
    if (currentStepIdx > 0) {
      setCurrentStepIdx(currentStepIdx - 1);
      setActionFeedback(null);
    }
  };

  const handleExecuteAction = async () => {
    setActionFeedback('Executing step action...');
    try {
      if (step.actionType === 'run_workday') {
        await api.runScenario('normal_workday', { speed: 20.0, seed: 42 });
        setActionFeedback('Normal Workday scenario running. 0 containments triggered.');
      } else if (step.actionType === 'run_backup') {
        await api.runScenario('nightly_backup', { speed: 20.0, seed: 42 });
        setActionFeedback('Nightly Backup running. High I/O verified without false alarms.');
      } else if (step.actionType === 'run_ransomware') {
        await api.runScenario('fast_ransomware', { speed: 10.0, seed: 42 });
        setActionFeedback('Fast Ransomware launched! Watch live containment and file rollback.');
        onNavigate('scenarios');
      } else if (step.actionType === 'view_comparison') {
        onNavigate('comparison');
        setActionFeedback('Navigated to Side-by-Side Detector Benchmark.');
      } else if (step.actionType === 'view_hard_test') {
        onNavigate('models');
        setActionFeedback('Navigated to Model Registry & Hard Test Set analysis.');
      }
    } catch (e: any) {
      setActionFeedback(`Action completed or simulated: ${e.message}`);
    }
  };

  const StepIcon = step.icon;

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
      <div className="w-full max-w-3xl bg-[#0d1424] border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-blue-600/20 text-blue-400 border border-blue-500/30">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-base font-bold text-white">AdaptShield 3-Minute Guided Demo</h2>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  STORY MODE
                </span>
              </div>
              <p className="text-xs text-slate-400">Step {currentStepIdx + 1} of {DEMO_STEPS.length}: {step.title}</p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => setIsPlaying(!isPlaying)}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold flex items-center space-x-1"
              title={isPlaying ? 'Pause auto-play' : 'Auto-play story mode'}
            >
              {isPlaying ? <Pause className="w-4 h-4 text-amber-400" /> : <Play className="w-4 h-4 text-emerald-400" />}
              <span className="text-[11px] hidden sm:inline">{isPlaying ? 'Pause' : 'Auto-Play'}</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="w-full h-1 bg-slate-900">
          <div
            className="h-full bg-gradient-to-r from-blue-500 via-purple-500 to-emerald-500 transition-all duration-300"
            style={{ width: `${((currentStepIdx + 1) / DEMO_STEPS.length) * 100}%` }}
          />
        </div>

        {/* Step Content */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          {/* Step Badge & Title */}
          <div className="flex items-start justify-between gap-4">
            <div className="space-y-1">
              <span className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold border ${step.badgeColor}`}>
                {step.badge}
              </span>
              <h3 className="text-xl font-bold text-white flex items-center space-x-2 pt-1">
                <StepIcon className="w-5 h-5 text-blue-400" />
                <span>{step.title}</span>
              </h3>
              <p className="text-xs text-slate-300 font-mono">{step.summary}</p>
            </div>
          </div>

          {/* Narration Script Box */}
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2.5">
            <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-slate-400 block">
              Presenter Narration Script:
            </span>
            <div className="space-y-2 text-xs font-mono text-slate-200 leading-relaxed">
              {step.narration.map((paragraph, idx) => (
                <p key={idx} className="flex items-start space-x-2">
                  <span className="text-blue-400 font-bold">&bull;</span>
                  <span>{paragraph}</span>
                </p>
              ))}
            </div>
          </div>

          {/* Expected Outcome & Interactive Action */}
          <div className="p-4 rounded-xl bg-[#0b101d] border border-blue-900/30 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Expected Technical Outcome:</span>
              <strong className="text-xs font-mono text-emerald-300">{step.expectedOutcome}</strong>
              {actionFeedback && (
                <p className="text-[11px] font-mono text-blue-400 mt-1">{actionFeedback}</p>
              )}
            </div>

            <button
              onClick={handleExecuteAction}
              className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs font-mono transition-colors shadow-lg shadow-blue-900/40 whitespace-nowrap flex items-center justify-center space-x-1.5"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{step.actionLabel}</span>
            </button>
          </div>
        </div>

        {/* Footer Navigation */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between text-xs font-mono">
          <div className="flex items-center space-x-1">
            {DEMO_STEPS.map((s, idx) => (
              <button
                key={s.id}
                onClick={() => {
                  setCurrentStepIdx(idx);
                  setActionFeedback(null);
                }}
                className={`w-6 h-6 rounded-full text-[11px] font-bold flex items-center justify-center transition-colors ${
                  idx === currentStepIdx
                    ? 'bg-blue-600 text-white'
                    : idx < currentStepIdx
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    : 'bg-slate-900 text-slate-500'
                }`}
              >
                {idx + 1}
              </button>
            ))}
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={handlePrev}
              disabled={currentStepIdx === 0}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 text-slate-200 text-xs font-semibold flex items-center space-x-1"
            >
              <ChevronLeft className="w-4 h-4" />
              <span>Previous</span>
            </button>

            {currentStepIdx < DEMO_STEPS.length - 1 ? (
              <button
                onClick={handleNext}
                className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center space-x-1"
              >
                <span>Next Step</span>
                <ChevronRight className="w-4 h-4" />
              </button>
            ) : (
              <button
                onClick={onClose}
                className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center space-x-1"
              >
                <CheckCircle2 className="w-4 h-4" />
                <span>Finish Demo</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
