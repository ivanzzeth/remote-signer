/**
 * Type definitions for MetaMask Snap
 */

export interface ConfigureParams {
  baseURL: string;
  apiKeyID: string;
  privateKey: string;
}

export interface SignParams {
  request: {
    chain_id: string;
    signer_address: string;
    sign_type: string;
    payload: any;
  };
  waitForApproval?: boolean;
}

export interface GetRequestParams {
  requestID: string;
}
