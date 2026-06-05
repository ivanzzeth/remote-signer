import { Link } from "react-router-dom";
import type { RequestBlocker } from "../lib/requestQueue";

export function RequestBlockerBanner({
  blocker,
  signerAddress,
  compact = false,
}: {
  blocker: RequestBlocker;
  signerAddress: string;
  compact?: boolean;
}) {
  const tone =
    blocker.kind === "signer_locked"
      ? "border-red-200 bg-red-50 text-red-900"
      : blocker.kind === "rule_matched_stuck"
        ? "border-amber-200 bg-amber-50 text-amber-950"
        : blocker.kind === "sign_failed"
          ? "border-orange-200 bg-orange-50 text-orange-950"
          : "border-ink-200 bg-ink-50 text-ink-800";

  return (
    <div
      data-testid="request-blocker-banner"
      data-blocker-kind={blocker.kind}
      className={`rounded-md border px-3 py-2 text-xs ${tone} ${compact ? "" : "mt-3"}`}
    >
      <p>{blocker.message}</p>
      {blocker.kind === "signer_locked" && (
        <p className="mt-1">
          <Link
            to={`/signers`}
            className="font-medium underline hover:no-underline"
          >
            Unlock signer {signerAddress.slice(0, 10)}…
          </Link>
          {" · "}
          <Link
            to="/hd-wallets"
            className="font-medium underline hover:no-underline"
          >
            HD Wallets
          </Link>
        </p>
      )}
    </div>
  );
}

export function LockedSignersQueueBanner({
  addresses,
}: {
  addresses: string[];
}) {
  if (addresses.length === 0) return null;
  const preview =
    addresses.length === 1
      ? addresses[0]
      : `${addresses[0]} (+${addresses.length - 1} more)`;

  return (
    <div
      data-testid="requests-locked-signers-banner"
      className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-900"
    >
      <p className="font-medium">
        {addresses.length === 1
          ? "A locked signer is blocking approvals on this page."
          : `${addresses.length} locked signers are blocking approvals on this page.`}
      </p>
      <p className="mt-1 font-mono text-xs">{preview}</p>
      <p className="mt-2 text-xs">
        Unlock on{" "}
        <Link to="/signers" className="font-medium underline hover:no-underline">
          Signers
        </Link>{" "}
        or{" "}
        <Link
          to="/hd-wallets"
          className="font-medium underline hover:no-underline"
        >
          HD Wallets
        </Link>{" "}
        — bulk approve will fail until then.
      </p>
    </div>
  );
}
