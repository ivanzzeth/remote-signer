import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  APIError,
  type ApproveRequest,
  type PreviewRuleResponse,
  type RuleMode,
} from "remote-signer-client";
import { Badge, Card, CodeBlock, ErrorBanner } from "./ui";
import { useConfirm } from "./feedback";
import { getClient } from "../lib/auth";
import { useCanApproveRequest } from "../lib/rbac";

type ApprovalRuleType =
  | "evm_address_list"
  | "evm_contract_method"
  | "evm_value_limit";

function isApprovalRuleType(value: string): value is ApprovalRuleType {
  return (
    value === "evm_address_list" ||
    value === "evm_contract_method" ||
    value === "evm_value_limit"
  );
}

/**
 * Admin-only approve/reject bar with optional whitelist-rule generation
 * (preview-rule + approve body fields).
 */
export function RequestApprovalPanel({
  requestID,
  generatableRuleTypes,
  suggestedMaxValue,
  busy,
  onBusy,
  onDone,
  onCancel,
}: {
  requestID: string;
  generatableRuleTypes: string[];
  suggestedMaxValue?: string;
  busy: boolean;
  onBusy: (v: boolean) => void;
  onDone: () => void;
  onCancel: () => void;
}) {
  const canApprove = useCanApproveRequest();
  const confirm = useConfirm();
  const ruleOptions = generatableRuleTypes.filter(isApprovalRuleType);
  const canGenerateRule = ruleOptions.length > 0;

  const [mutationError, setMutationError] = useState<string | null>(null);
  const [withRule, setWithRule] = useState(false);
  const [ruleType, setRuleType] = useState<ApprovalRuleType>("evm_address_list");
  const [ruleMode, setRuleMode] = useState<RuleMode>("whitelist");
  const [ruleName, setRuleName] = useState("");
  const [maxValue, setMaxValue] = useState("");
  const [preview, setPreview] = useState<PreviewRuleResponse | null>(null);
  const [generatedRuleID, setGeneratedRuleID] = useState<string | null>(null);

  useEffect(() => {
    if (ruleOptions.length === 0) {
      setWithRule(false);
      setPreview(null);
      return;
    }
    if (!ruleOptions.includes(ruleType)) {
      setRuleType(ruleOptions[0]!);
    }
  }, [ruleOptions, ruleType]);

  useEffect(() => {
    if (
      ruleType === "evm_value_limit" &&
      suggestedMaxValue &&
      !maxValue.trim()
    ) {
      setMaxValue(suggestedMaxValue);
    }
  }, [ruleType, suggestedMaxValue, maxValue]);

  if (!canApprove) return null;

  async function runApprove(approved: boolean) {
    const client = getClient();
    if (!client) return;
    if (!approved) {
      const ok = await confirm({
        title: "Reject request",
        message: "Reject this request? It cannot be re-approved later.",
        confirmLabel: "Reject",
        tone: "danger",
      });
      if (!ok) return;
    }
    onBusy(true);
    setMutationError(null);
    setGeneratedRuleID(null);
    try {
      const body: ApproveRequest = { approved };
      if (approved && withRule && canGenerateRule) {
        body.rule_type = ruleType;
        body.rule_mode = ruleMode;
        if (ruleName.trim()) body.rule_name = ruleName.trim();
        if (ruleType === "evm_value_limit" && maxValue.trim()) {
          body.max_value = maxValue.trim();
        }
      }
      const resp = await client.evm.requests.approve(requestID, body);
      if (resp.generated_rule?.id) {
        setGeneratedRuleID(resp.generated_rule.id);
      }
      onDone();
    } catch (e) {
      setMutationError(formatErr(e));
    } finally {
      onBusy(false);
    }
  }

  async function runPreview() {
    const client = getClient();
    if (!client) return;
    onBusy(true);
    setMutationError(null);
    setPreview(null);
    try {
      const resp = await client.evm.requests.previewRule(requestID, {
        rule_type: ruleType,
        rule_mode: ruleMode,
        ...(ruleName.trim() ? { rule_name: ruleName.trim() } : {}),
        ...(ruleType === "evm_value_limit" && maxValue.trim()
          ? { max_value: maxValue.trim() }
          : {}),
      });
      setPreview(resp);
    } catch (e) {
      setMutationError(formatErr(e));
    } finally {
      onBusy(false);
    }
  }

  return (
    <div
      className="fixed inset-x-0 bottom-0 z-10 border-t border-ink-200 bg-white/95 backdrop-blur"
      data-testid="request-approval-panel"
    >
      <div className="mx-auto max-w-5xl space-y-3 px-8 py-3">
        {mutationError && <ErrorBanner msg={mutationError} />}
        {generatedRuleID && (
          <div className="rounded-md border border-green-200 bg-green-50 px-3 py-2 text-xs text-green-900">
            Whitelist rule created:{" "}
            <Link to="/rules" className="font-mono text-accent-600 hover:underline">
              {generatedRuleID}
            </Link>
          </div>
        )}

        <div className="flex flex-wrap items-end justify-between gap-3">
          <div className="text-xs text-ink-500">
            Waiting for a decision — approve hands this off to the signer.
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={onCancel}
              className="rounded-md border border-ink-200 px-3 py-1.5 text-sm text-ink-700 hover:bg-ink-100"
            >
              Back
            </button>
            <button
              type="button"
              onClick={() => runApprove(false)}
              disabled={busy}
              className="rounded-md border border-red-300 px-3 py-1.5 text-sm text-red-700 hover:bg-red-50 disabled:opacity-50"
            >
              Reject
            </button>
            <button
              type="button"
              onClick={() => runApprove(true)}
              disabled={busy}
              className="rounded-md bg-accent-500 px-4 py-1.5 text-sm font-medium text-white hover:bg-accent-600 disabled:opacity-50"
            >
              {withRule && canGenerateRule ? "Approve + rule" : "Approve"}
            </button>
          </div>
        </div>

        {canGenerateRule ? (
          <Card title="Optional: approve and create whitelist rule">
            <p className="mb-3 text-xs text-ink-600">
              Only rule types derivable from this request are listed below.
            </p>
            <label className="mb-3 flex items-center gap-2 text-sm text-ink-700">
              <input
                type="checkbox"
                checked={withRule}
                onChange={(e) => setWithRule(e.target.checked)}
              />
              Generate a whitelist rule from this request when approving
            </label>
            {withRule && (
              <div className="space-y-3">
                <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                  <Field label="Rule type">
                    <select
                      value={ruleType}
                      onChange={(e) => {
                        const next = e.target.value;
                        if (isApprovalRuleType(next)) setRuleType(next);
                      }}
                      className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
                      data-testid="approval-rule-type"
                    >
                      {ruleOptions.map((t) => (
                        <option key={t} value={t}>
                          {t}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Mode">
                    <select
                      value={ruleMode}
                      onChange={(e) =>
                        setRuleMode(e.target.value as RuleMode)
                      }
                      className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
                    >
                      <option value="whitelist">whitelist</option>
                      <option value="blocklist">blocklist</option>
                    </select>
                  </Field>
                  <Field label="Rule name (optional)">
                    <input
                      type="text"
                      value={ruleName}
                      onChange={(e) => setRuleName(e.target.value)}
                      className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
                    />
                  </Field>
                </div>
                {ruleType === "evm_value_limit" && (
                  <Field label="Max value (wei, decimal)">
                    <input
                      type="text"
                      value={maxValue}
                      onChange={(e) => setMaxValue(e.target.value)}
                      placeholder="1000000000000000000"
                      className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-sm"
                    />
                  </Field>
                )}
                <button
                  type="button"
                  onClick={runPreview}
                  disabled={busy}
                  className="rounded-md border border-ink-200 px-3 py-1 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
                >
                  Preview rule
                </button>
                {preview && (
                  <div className="mt-2 space-y-2">
                    <div className="flex flex-wrap gap-2 text-xs">
                      <Badge>{preview.type}</Badge>
                      <Badge tone="green">{preview.mode}</Badge>
                      <span className="font-mono text-ink-600">{preview.name}</span>
                    </div>
                    <CodeBlock
                      body={JSON.stringify(preview.config, null, 2)}
                      lang="json"
                      maxH={16}
                      title="Preview config"
                    />
                  </div>
                )}
              </div>
            )}
          </Card>
        ) : (
          <p
            className="text-xs text-ink-500"
            data-testid="request-approval-no-generatable-rules"
          >
            This request cannot auto-generate whitelist rules from its payload —
            approve without creating a rule.
          </p>
        )}
      </div>
    </div>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <div className="mb-1 text-[11px] uppercase tracking-wide text-ink-500">
        {label}
      </div>
      {children}
    </div>
  );
}

function formatErr(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
