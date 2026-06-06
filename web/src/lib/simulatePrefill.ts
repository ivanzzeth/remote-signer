import type { RequestStatusResponse } from "remote-signer-client";

export interface SimulateFormPrefill {
  chainID: string;
  from: string;
  to: string;
  value: string;
  data: string;
  gas: string;
}

interface TxPayload {
  to?: string;
  value?: string;
  data?: string;
  gas?: number | string;
}

interface DecodedCalldata {
  to?: string;
  value?: string;
  raw_data?: string;
  contract?: string;
}

/** Build simulate form fields from a sign request detail response. */
export function prefillFromRequest(
  req: RequestStatusResponse,
  decodedCalldata?: unknown,
): SimulateFormPrefill | null {
  if (req.sign_type !== "transaction") {
    return null;
  }

  const tx = (req.payload as { transaction?: TxPayload } | undefined)
    ?.transaction;
  const decoded = parseDecodedCalldata(decodedCalldata);

  const to = tx?.to || decoded?.to || decoded?.contract || "";
  const value = tx?.value ?? decoded?.value ?? "0";
  const data = tx?.data || decoded?.raw_data || "0x";
  const gas =
    tx?.gas !== undefined && tx.gas !== null ? String(tx.gas) : "";

  if (!to) {
    return null;
  }

  return {
    chainID: req.chain_id,
    from: req.signer_address,
    to,
    value: value || "0",
    data: data || "0x",
    gas,
  };
}

function parseDecodedCalldata(value: unknown): DecodedCalldata | null {
  if (!value) return null;
  let parsed: unknown = value;
  if (typeof value === "string") {
    try {
      parsed = JSON.parse(value);
    } catch {
      return null;
    }
  }
  if (!parsed || typeof parsed !== "object") return null;
  return parsed as DecodedCalldata;
}
