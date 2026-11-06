/** Loader-v3 refunds the buffer before funding ProgramData. Do not sum both. */
export function deploymentBudget(programRent: number, programDataRent: number, bufferRent: number, feeReserve = 20_000_000) {
  for (const amount of [programRent, programDataRent, bufferRent, feeReserve]) {
    if (!Number.isSafeInteger(amount) || amount < 0) throw new Error('Invalid deployment rent quote.');
  }
  const retainedRent = programRent + programDataRent;
  const peakStorageFunding = programRent + Math.max(programDataRent, bufferRent);
  const plannedFunding = peakStorageFunding + feeReserve;
  if (!Number.isSafeInteger(plannedFunding)) throw new Error('Deployment quote exceeds safe precision.');
  return { retainedRent, peakStorageFunding, feeReserve, plannedFunding };
}
