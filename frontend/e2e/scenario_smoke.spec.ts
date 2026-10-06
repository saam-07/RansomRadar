import { test, expect } from '@playwright/test';
import * as path from 'path';

test.describe('AdaptShield Scenario Runner E2E Smoke Test', () => {
  test('runs fast_ransomware scenario, verifies containment, and captures demo screenshots', async ({ page }) => {
    // 1. Visit Live Dashboard
    await page.goto('http://localhost:5173');
    await expect(page.getByText('ADAPTSHIELD', { exact: true })).toBeVisible();

    // 2. Navigate to Scenario Runner page
    const scenarioTab = page.getByRole('button', { name: /Scenario Runner/i });
    await scenarioTab.click();
    await expect(page.getByText('Automated Scenario Runner & Containment Visualizer')).toBeVisible();

    // Verify scenario cards exist
    await expect(page.getByRole('heading', { name: 'Fast Ransomware Outbreak' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Mixed Multi-Process Chaos' })).toBeVisible();

    // 3. Select Fast Ransomware Outbreak and execute
    await page.getByRole('heading', { name: 'Fast Ransomware Outbreak' }).click();
    const runBtn = page.getByRole('button', { name: /Run Scenario/i });
    await expect(runBtn).toBeVisible();
    await runBtn.click();

    // 4. Assert containment occurs
    // Wait for containment or frozen/locked/restored files
    await expect(
      page.locator('text=OVERLAY FROZEN').or(page.locator('text=Locked')).or(page.locator('text=Restored')).first()
    ).toBeVisible({ timeout: 15000 });

    // Wait 2 seconds for visual updates to stabilize
    await page.waitForTimeout(2000);

    // Capture screenshot for filesystem visualizer demo
    const filesystemScreenshotPath = 'docs/demo/filesystem_rollback.png';
    await page.screenshot({ path: filesystemScreenshotPath, fullPage: true });

    // 5. Navigate to Detector Comparison tab
    const comparisonTab = page.getByRole('button', { name: /Detector Comparison/i });
    await comparisonTab.click();
    await expect(page.getByText('Detector Comparison Benchmark')).toBeVisible();

    // Trigger Side-by-Side benchmark
    const runBenchmarkBtn = page.getByRole('button', { name: /Run Side-by-Side/i });
    await runBenchmarkBtn.click();

    // Assert comparison table & cards are loaded
    await expect(page.getByText('Detailed Benchmark Comparison Table')).toBeVisible({ timeout: 15000 });
    await expect(page.getByText('Rule-Based Heuristic').first()).toBeVisible();
    await expect(page.getByText('Random Forest').first()).toBeVisible();
    await expect(page.getByText('XGBoost Classifier').first()).toBeVisible();

    // Capture screenshot for detector comparison demo
    const comparisonScreenshotPath = 'docs/demo/detector_comparison.png';
    await page.screenshot({ path: comparisonScreenshotPath, fullPage: true });
  });
});
