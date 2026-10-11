/**
 * The three-level risk label (high / risk / none) recorded with every scan
 * entry. Risk is evidence-based and independent of the suggested disposition:
 *
 *   - `high`  a high-confidence malicious review, or a high/critical
 *             dependency advisory
 *   - `risk`  other advisories, behavior that needs review, or an incomplete
 *             check (truncated files, failed or unknown audit, open review)
 *   - `none`  nothing found in this scan — not a safety guarantee
 *
 * The browser half (client.js) keeps an identical copy for records written by
 * older versions; test/risk.test.js keeps the two in step.
 *
 * @module dsh-plugin-security/risk
 */

export const RISK_LEVELS = Object.freeze(['high', 'risk', 'none']);

const HIGH_ADVISORY = ['critical', 'high'];

/** Advisories as stored on a cached record or a fresh scan result. */
function advisoriesOf(plugin) {
  if (Array.isArray(plugin?.depsAdvisories)) return plugin.depsAdvisories;
  if (Array.isArray(plugin?.deps?.advisories)) return plugin.deps.advisories;
  return Object.values(plugin?.deps?.results ?? {}).flatMap((result) => result?.advisories ?? []);
}

/**
 * @param {object} plugin a scan entry or report row
 * @returns {{level: 'high'|'risk'|'none', reason: string}}
 */
export function riskOf(plugin) {
  const review = plugin?.review ?? null;
  const deps = plugin?.deps?.worst ?? 'none';
  const advisories = advisoriesOf(plugin);
  const benignHigh = review?.verdict === 'benign' && review.confidence === 'high';
  if (review?.verdict === 'malicious' && review.confidence === 'high') return { level: 'high', reason: 'riskConfirmed' };
  if (HIGH_ADVISORY.includes(deps) || advisories.some((a) => HIGH_ADVISORY.includes(a?.severity))) {
    return { level: 'high', reason: 'riskAdvisory' };
  }
  if (deps !== 'none' || advisories.length) return { level: 'risk', reason: 'riskAdvisory' };
  if (plugin?.filesTruncated || plugin?.source === 'missing' || plugin?.deps?.errors?.length || plugin?.deps?.unknown === true ||
    Object.values(plugin?.deps?.results ?? {}).some((d) => d?.unknown)) return { level: 'risk', reason: 'riskIncomplete' };
  if (review && !benignHigh) return { level: 'risk', reason: 'riskIncomplete' };
  const findings = plugin?.findings ?? plugin?.screening?.findings ?? [];
  if (!benignHigh && ((plugin?.screening?.signal?.level ?? 'none') !== 'none' ||
    findings.some((f) => f.kind !== 'capability' && f.scope !== 'support' && HIGH_ADVISORY.includes(f.severity)))) {
    return { level: 'risk', reason: 'riskBehavior' };
  }
  return { level: 'none', reason: 'riskClear' };
}
