import { describe, expect, it } from 'vitest';
import { deploymentBudget } from '../src/lib/deployment-cost.js';

describe('initial loader-v3 deployment budget', () => {
  it('does not double-count the refunded buffer deposit', () => {
    const quote = deploymentBudget(833_120, 1_895_109_240, 1_895_068_600);
    expect(quote.retainedRent).toBe(1_895_942_360);
    expect(quote.peakStorageFunding).toBe(quote.retainedRent);
    expect(quote.plannedFunding).toBe(1_915_942_360);
    expect(quote.plannedFunding).toBeLessThan(1_920_000_000);
  });
  it('budgets for the larger temporary allocation without summing deposits', () => {
    expect(deploymentBudget(100, 300, 400, 20)).toEqual({
      retainedRent: 400, peakStorageFunding: 500, feeReserve: 20, plannedFunding: 520,
    });
  });
  it('does not describe the fee reserve as consumed fees', () => {
    const quote = deploymentBudget(100, 300, 200, 0);
    expect(quote.plannedFunding).toBe(400);
    expect(quote.feeReserve).toBe(0);
  });
  it('rejects invalid RPC quotes and unsafe totals', () => {
    for (const invalid of [-1, NaN, Infinity, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => deploymentBudget(invalid, 100, 100)).toThrow();
    }
    expect(() => deploymentBudget(Number.MAX_SAFE_INTEGER, 1, 1)).toThrow();
  });
});
