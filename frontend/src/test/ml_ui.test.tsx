import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DatasetsPage } from '../pages/DatasetsPage';
import { ModelsPage } from '../pages/ModelsPage';
import { api } from '../api/client';

// Mock API client
vi.mock('../api/client', () => ({
  api: {
    getDatasets: vi.fn(),
    getDatasetCard: vi.fn(),
    getDatasetStats: vi.fn(),
    getDatasetSample: vi.fn(),
    generateDataset: vi.fn(),
    getModels: vi.fn(),
    getModelEvaluation: vi.fn(),
    activateModel: vi.fn(),
    trainModel: vi.fn(),
    getTrainingJobStatus: vi.fn(),
    predictFeatures: vi.fn(),
  },
}));

describe('DatasetsPage Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (api.getDatasets as any).mockResolvedValue({
      generator_version: '1.0.0',
      schema_version: '1.0.0',
      files: {
        train: { rows: 3600, runs: 240 },
        val: { rows: 1200, runs: 80 },
        test: { rows: 1200, runs: 80 },
        hard_test: { rows: 1800, runs: 120 },
      },
      feature_columns: ['mod_rate', 'rename_rate', 't1_mean_entropy'],
      simulated: true,
    });
    (api.getDatasetCard as any).mockResolvedValue({
      content: '# AdaptShield Dataset Card\nSynthetic benchmark traces.',
      simulated: true,
    });
    (api.getDatasetStats as any).mockResolvedValue({
      split: 'train',
      total_rows: 3600,
      class_distribution: { benign: 1080, backup: 720, oltp: 720, ransomware: 1080 },
      feature_statistics: {
        t1_mean_entropy: {
          benign: { mean: 4.2, p50: 4.1, min: 2.0, max: 5.5, std: 0.4 },
          ransomware: { mean: 7.9, p50: 7.95, min: 6.8, max: 8.0, std: 0.1 },
        },
      },
      simulated: true,
    });
    (api.getDatasetSample as any).mockResolvedValue({
      split: 'train',
      total_rows: 3600,
      sample_size: 2,
      rows: [
        { pid: 1001, scenario: 'normal_workday', label: 'benign', window_idx: 1, event_count: 15, mod_rate: 4.0, rename_rate: 0.0, concentration_gini: 0.2, t1_mean_entropy: null, source: 'synthetic' },
        { pid: 4099, scenario: 'fast_ransomware', label: 'ransomware', window_idx: 4, event_count: 90, mod_rate: 45.0, rename_rate: 20.0, concentration_gini: 0.8, t1_mean_entropy: 7.9, source: 'synthetic' },
      ],
      simulated: true,
    });
  });

  it('renders dataset overview, schema table, and split controls', async () => {
    render(<DatasetsPage />);

    await waitFor(() => {
      expect(screen.getByText('Benchmark Datasets Explorer')).toBeInTheDocument();
      expect(screen.getByText('TRAIN (3600 rows)')).toBeInTheDocument();
      expect(screen.getByText('Feature Schema Specification (11 Features)')).toBeInTheDocument();
      expect(screen.getByText('t1_mean_entropy')).toBeInTheDocument();
      expect(screen.getByText('Regenerate Datasets')).toBeInTheDocument();
    });
  });

  it('navigates to trace samples tab and displays sample data', async () => {
    render(<DatasetsPage />);

    await waitFor(() => {
      expect(screen.getByText('Trace Samples')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Trace Samples'));

    await waitFor(() => {
      expect(screen.getByText('fast_ransomware')).toBeInTheDocument();
      expect(screen.getByText('normal_workday')).toBeInTheDocument();
      expect(screen.getByText('1001')).toBeInTheDocument();
    });
  });
});

describe('ModelsPage Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (api.getModels as any).mockImplementation(() => Promise.resolve({
      active_model: 'xgboost',
      models: [
        {
          name: 'xgboost',
          classifier_type: 'xgboost',
          active: true,
          metrics: { accuracy: 0.992, f1: 0.991, roc_auc: 0.999 },
          data_source: 'synthetic',
        },
        {
          name: 'random_forest',
          classifier_type: 'random_forest',
          active: false,
          metrics: { accuracy: 0.985, f1: 0.984, roc_auc: 0.995 },
          data_source: 'synthetic',
        },
      ],
    }));
    (api.getModelEvaluation as any).mockResolvedValue({
      model_name: 'xgboost',
      metrics: {
        accuracy: 0.992,
        precision: 0.994,
        recall: 0.988,
        f1: 0.991,
        roc_auc: 0.999,
        hard_test: {
          accuracy: 0.673,
          f1: 0.515,
          recall: 0.347,
          roc_auc: 0.868,
        },
        feature_importances: [
          { feature: 't1_mean_entropy', importance: 0.214 },
          { feature: 'rename_rate', importance: 0.143 },
        ],
      },
    });
    (api.predictFeatures as any).mockResolvedValue({
      prediction: 'ransomware',
      probability_ransomware: 0.965,
      class_probabilities: { benign: 0.035, ransomware: 0.965 },
      explanation: { summary: 'Extreme write entropy and elevated rename operations.' },
      model_name: 'xgboost',
      data_source: 'synthetic',
      simulated: true,
    });
  });

  it('renders model registry table with ACTIVE status and metrics', async () => {
    render(<ModelsPage />);

    await waitFor(() => {
      expect(screen.getByText('Model Registry & Training Studio')).toBeInTheDocument();
    });

    expect(api.getModels).toHaveBeenCalled();

    await waitFor(() => {
      expect(screen.getAllByText('random_forest').length).toBeGreaterThan(0);
    });

    expect(screen.getByText('Model Name')).toBeInTheDocument();
  });

  it('displays hard test set degradation banner and Try It widget with live inference', async () => {
    render(<ModelsPage />);

    await waitFor(() => {
      expect(screen.getByText(/Hard Test Set Generalization/i)).toBeInTheDocument();
      expect(screen.getByText(/Interactive "Try It" Inference Widget/i)).toBeInTheDocument();
      expect(screen.getByText('Fast Ransomware')).toBeInTheDocument();
      expect(screen.getByText('Normal Workday')).toBeInTheDocument();
    });

    // Click Fast Ransomware preset
    fireEvent.click(screen.getByText('Fast Ransomware'));

    await waitFor(() => {
      expect(api.predictFeatures).toHaveBeenCalled();
    });
  });
});
