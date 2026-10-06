/**
 * Typed REST API client for AdaptShield backend.
 */

import { AlertItem, ProcessItem, ScenarioDefinition, ScenarioRunDetail, SystemStatus } from '../types/api';

const API_BASE = '/api';

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${url}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });

  if (!response.ok) {
    let errorDetail = response.statusText;
    try {
      const errJson = await response.json();
      errorDetail = errJson.detail || JSON.stringify(errJson);
    } catch {
      // ignore
    }
    throw new Error(`API Error (${response.status}): ${errorDetail}`);
  }

  return response.json();
}

export const api = {
  // System Status & Control
  getStatus: (): Promise<SystemStatus> => fetchJson<SystemStatus>('/status'),
  getHealth: (): Promise<{ status: string; version: string; simulated: boolean }> => fetchJson('/health'),
  setControl: (params: { mode?: string; policy?: string; detector?: string; reset_storm?: boolean }) =>
    fetchJson('/control', {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  // Processes
  getProcesses: (): Promise<{ processes: ProcessItem[]; total: number; simulated: boolean }> =>
    fetchJson('/processes'),

  // Alerts & Containment
  getAlerts: (params?: { limit?: number; offset?: number; status?: string }): Promise<{ alerts: AlertItem[]; total: number; simulated: boolean }> => {
    const search = new URLSearchParams();
    if (params?.limit) search.set('limit', String(params.limit));
    if (params?.offset) search.set('offset', String(params.offset));
    if (params?.status) search.set('status', params.status);
    const query = search.toString() ? `?${search.toString()}` : '';
    return fetchJson(`/alerts${query}`);
  },

  getAlertDetail: (id: string): Promise<AlertItem> => fetchJson(`/alerts/${id}`),

  releaseProcess: (pid: number, reason?: string) =>
    fetchJson('/containment/release', {
      method: 'POST',
      body: JSON.stringify({ pid, action: 'release', reason }),
    }),

  confirmProcess: (pid: number, reason?: string) =>
    fetchJson('/containment/confirm', {
      method: 'POST',
      body: JSON.stringify({ pid, action: 'confirm', reason }),
    }),

  // Scenarios
  getScenarios: (): Promise<ScenarioDefinition[]> => fetchJson('/scenarios'),
  runScenario: (scenario_name: string, options?: { detector?: string; policy?: string; speed?: number; seed?: number }) =>
    fetchJson('/scenarios/run', {
      method: 'POST',
      body: JSON.stringify({ scenario_name, ...options }),
    }),
  stopScenario: () => fetchJson('/scenarios/stop', { method: 'POST' }),
  resetScenarioState: () => fetchJson('/scenarios/reset', { method: 'POST' }),
  getScenarioRuns: (): Promise<ScenarioRunDetail[]> => fetchJson('/scenarios/runs'),
  getScenarioRunDetail: (runId: string): Promise<ScenarioRunDetail> => fetchJson(`/scenarios/runs/${runId}`),
  getVirtualFilesystem: (): Promise<{ summary: any; simulated: boolean }> => fetchJson('/scenarios/filesystem'),
  compareDetectors: (params: { scenario_name: string; seed?: number }): Promise<{ scenario: string; seed: number; comparison: Record<string, any>; simulated: boolean }> =>
    fetchJson('/scenarios/compare', {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  // Datasets
  getDatasets: () => fetchJson('/datasets'),
  getDatasetCard: (): Promise<{ content: string; simulated: boolean }> => fetchJson('/datasets/card'),
  getDatasetSample: (split: string, limit = 20, label?: string): Promise<{ split: string; total_rows: number; sample_size: number; rows: Record<string, any>[]; simulated: boolean }> => {
    let url = `/datasets/${split}/sample?limit=${limit}`;
    if (label) url += `&label=${label}`;
    return fetchJson(url);
  },
  getDatasetStats: (split: string): Promise<{ split: string; total_rows: number; class_distribution: Record<string, number>; feature_statistics: Record<string, any>; simulated: boolean }> =>
    fetchJson(`/datasets/${split}/stats`),
  generateDataset: (params: { seed?: number; imbalanced?: boolean }) =>
    fetchJson('/datasets/generate', {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  // Models
  getModels: () => fetchJson('/models'),
  getModelEvaluation: (model_name: string) => fetchJson(`/models/${model_name}/evaluation`),
  activateModel: (model_name: string) =>
    fetchJson('/models/activate', {
      method: 'POST',
      body: JSON.stringify({ model_name }),
    }),
  trainModel: (params: { classifier_type: string; model_name?: string; hyperparameters?: Record<string, any> }) =>
    fetchJson('/models/train', {
      method: 'POST',
      body: JSON.stringify(params),
    }),
  getTrainingJobStatus: (jobId: string) => fetchJson(`/models/training/${jobId}`),
  predictFeatures: (features: Record<string, any>) =>
    fetchJson('/models/predict', {
      method: 'POST',
      body: JSON.stringify({ features }),
    }),
};
