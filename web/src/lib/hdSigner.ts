/** Minimal signer fields used for HD wallet display helpers. */
export type HDSignerDisplay = {
  type: string;
  address: string;
  primary_address?: string;
  hd_derivation_index?: number;
};

/** True when an hd_wallet signer is the wallet primary (derivation index 0). */
export function isHDWalletPrimary(s: HDSignerDisplay): boolean {
  if (s.type !== "hd_wallet") return false;
  if (s.hd_derivation_index === 0) return true;
  if (
    s.hd_derivation_index == null &&
    s.primary_address &&
    s.address.toLowerCase() === s.primary_address.toLowerCase()
  ) {
    return true;
  }
  return false;
}
