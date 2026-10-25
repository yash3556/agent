import { detectIndiaIdentity } from "./india.js";
import { detectFinancialData } from "./financial.js";
import { detectCredentialSecrets } from "./credentials.js";

export const deterministicRegistry = [detectIndiaIdentity, detectFinancialData, detectCredentialSecrets];

export function runDeterministicRegistry(text: string) {
  return deterministicRegistry.flatMap((detector) => detector(text));
}
