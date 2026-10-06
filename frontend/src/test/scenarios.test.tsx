import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { FilesystemGrid, VirtualFileItem } from '../components/scenarios/FilesystemGrid';
import { ScenarioReportModal } from '../components/scenarios/ScenarioReportModal';
import { ScenarioRunnerPage } from '../pages/ScenarioRunnerPage';
import { DetectorComparisonPage } from '../pages/DetectorComparisonPage';
import { ScenarioRunDetail } from '../types/api';
import { api } from '../api/client';

// Mock API client
vi.mock('../api/client', () => ({
  api: {
    getScenarios: vi.fn(),
    getVirtualFilesystem: vi.fn(),
    runScenario: vi.fn(),
    stopScenario: vi.fn(),
    resetScenarioState: vi.fn(),
    compareDetectors: vi.fn(),
    getScenarioRuns: vi.fn(),
  },
}));

describe('FilesystemGrid Component', () => {
  const sampleFiles: VirtualFileItem[] = [
    { file_id: 'file_001', path: '/var/data/doc_1.pdf', name: 'doc_1.pdf', status: 'healthy', size_kb: 120, size_bytes: 122880 },
    { file_id: 'file_002', path: '/var/data/contract.docx', name: 'contract.docx', status: 'encrypted', size_kb: 450, size_bytes: 460800 },
    { file_id: 'file_003', path: '/var/data/db.sqlite', name: 'db.sqlite', status: 'restored', size_kb: 2048, size_bytes: 2097152 },
    { file_id: 'file_004', path: '/var/data/finance.xlsx', name: 'finance.xlsx', status: 'frozen', size_kb: 310, size_bytes: 317440 },
  ];

  it('renders filesystem header and total file count', () => {
    render(<FilesystemGrid files={sampleFiles} isFrozen={false} />);
    expect(screen.getByText('Virtual Filesystem State')).toBeInTheDocument();
    expect(screen.getByText(/All \(4\)/i)).toBeInTheDocument();
  });

  it('displays accurate status counts for intact, encrypted, restored, and frozen', () => {
    render(<FilesystemGrid files={sampleFiles} isFrozen={true} />);
    expect(screen.getByText(/Encrypted \(1\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Restored \(1\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Intact \(1\)/i)).toBeInTheDocument();
    expect(screen.getByText('OVERLAY FROZEN')).toBeInTheDocument();
  });

  it('filters files when clicking category filter tabs', () => {
    render(<FilesystemGrid files={sampleFiles} isFrozen={false} />);
    const encryptedFilterBtn = screen.getByText(/Encrypted \(1\)/i);
    fireEvent.click(encryptedFilterBtn);
    expect(screen.getByText('contract.docx.locked')).toBeInTheDocument();
    expect(screen.queryByText('doc_1.pdf')).not.toBeInTheDocument();
  });
});

describe('ScenarioReportModal Component', () => {
  const sampleRun: ScenarioRunDetail = {
    id: 'run-123',
    scenario_name: 'fast_ransomware',
    detector: 'xgboost',
    policy: 'immediate',
    speed: 5.0,
    seed: 42,
    status: 'completed',
    started_at: '2026-10-06T12:00:00Z',
    completed_at: '2026-10-06T12:00:10Z',
    total_windows: 25,
    distinct_pids: 4,
    contained_pids: [7001],
    time_to_detect_windows: 4,
    time_to_detect_seconds: 8.0,
    wall_time_seconds: 2.1,
    files_encrypted: 3,
    files_restored: 12,
    files_intact: 45,
    panic_tripped: false,
    summary: { attack_vector: 'bulk_encrypt' },
    simulated: true,
  };

  it('renders post-run report metrics and export actions', () => {
    const handleClose = vi.fn();
    render(<ScenarioReportModal run={sampleRun} isOpen={true} onClose={handleClose} />);

    expect(screen.getByText('Benchmark Evaluation Report')).toBeInTheDocument();
    expect(screen.getByText('fast_ransomware')).toBeInTheDocument();
    expect(screen.getByText('8s')).toBeInTheDocument();
    expect(screen.getByText('Export JSON')).toBeInTheDocument();
    expect(screen.getByText('Export PDF / Print')).toBeInTheDocument();
  });
});

describe('ScenarioRunnerPage Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (api.getScenarios as any).mockResolvedValue([
      {
        id: 'fast_ransomware',
        name: 'fast_ransomware',
        family: 'ransomware',
        description: 'Rapid batch encryption across canary and decoy files.',
        duration_windows: 30,
        processes_count: 1,
        expected_outcome: 'Immediate detection within 3-5 windows.',
      },
      {
        id: 'mixed_chaos',
        name: 'mixed_chaos',
        family: 'mixed',
        description: 'Two attackers with concurrent benign workloads.',
        duration_windows: 40,
        processes_count: 4,
        expected_outcome: 'Independent containment of both attackers without stopping backup.',
      },
    ]);
    (api.getVirtualFilesystem as any).mockResolvedValue({
      summary: {
        total_files: 4,
        status_counts: { healthy: 4, encrypted: 0, restored: 0, frozen: 0 },
        files: [],
      },
      simulated: true,
    });
  });

  it('renders scenario options and triggers execution', async () => {
    render(<ScenarioRunnerPage wsEvents={[]} />);

    await waitFor(() => {
      expect(screen.getByText('Automated Scenario Runner & Containment Visualizer')).toBeInTheDocument();
      expect(screen.getAllByText('fast_ransomware').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText('mixed_chaos')).toBeInTheDocument();
    });

    const runButton = screen.getByRole('button', { name: /Run Scenario/i });
    expect(runButton).toBeInTheDocument();

    (api.runScenario as any).mockResolvedValue({ success: true });
    fireEvent.click(runButton);

    await waitFor(() => {
      expect(api.runScenario).toHaveBeenCalledWith('fast_ransomware', expect.objectContaining({
        detector: 'xgboost',
        policy: 'immediate',
        speed: 5.0,
        seed: 42,
      }));
    });
  });
});

describe('DetectorComparisonPage Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (api.getScenarios as any).mockResolvedValue([
      {
        id: 'fast_ransomware',
        name: 'fast_ransomware',
        family: 'ransomware',
        description: 'Rapid bulk encryption',
        duration_windows: 30,
        processes_count: 1,
        expected_outcome: 'Early containment',
      },
    ]);
    (api.compareDetectors as any).mockResolvedValue({
      scenario: 'fast_ransomware',
      seed: 42,
      comparison: {
        rule_based: {
          detector: 'rule_based',
          total_windows: 30,
          time_to_detect_windows: 6,
          time_to_detect_seconds: 12.0,
          contained_pids: [7001],
          files_lost: 4,
          files_saved: 56,
          files_restored: 8,
          false_alarms: 0,
        },
        random_forest: {
          detector: 'random_forest',
          total_windows: 30,
          time_to_detect_windows: 4,
          time_to_detect_seconds: 8.0,
          contained_pids: [7001],
          files_lost: 2,
          files_saved: 58,
          files_restored: 10,
          false_alarms: 0,
        },
        xgboost: {
          detector: 'xgboost',
          total_windows: 30,
          time_to_detect_windows: 3,
          time_to_detect_seconds: 6.0,
          contained_pids: [7001],
          files_lost: 1,
          files_saved: 59,
          files_restored: 11,
          false_alarms: 0,
        },
      },
      simulated: true,
    });
  });

  it('renders side-by-side comparison cards and table', async () => {
    render(<DetectorComparisonPage />);

    await waitFor(() => {
      expect(screen.getByText('Detector Comparison Benchmark')).toBeInTheDocument();
      expect(screen.getByText('Rule-Based Heuristic')).toBeInTheDocument();
      expect(screen.getByText('Random Forest')).toBeInTheDocument();
      expect(screen.getByText('XGBoost Classifier')).toBeInTheDocument();
    });

    expect(screen.getByText('Detailed Benchmark Comparison Table')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Run Side-by-Side/i })).toBeInTheDocument();
  });
});
