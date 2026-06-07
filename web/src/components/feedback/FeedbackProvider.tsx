import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ReactNode,
  type RefObject,
} from "react";

export type ToastTone = "success" | "error" | "info";

export interface ToastInput {
  title: string;
  description?: string;
  tone?: ToastTone;
  durationMs?: number;
}

export interface ConfirmOptions {
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  tone?: "default" | "danger";
}

export interface PromptOptions {
  title: string;
  message?: string;
  placeholder?: string;
  defaultValue?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  tone?: "default" | "danger";
  multiline?: boolean;
}

interface ToastItem extends ToastInput {
  id: string;
}

interface PendingConfirm extends ConfirmOptions {
  resolve: (accepted: boolean) => void;
}

interface PendingPrompt extends PromptOptions {
  resolve: (value: string | null) => void;
}

interface FeedbackContextValue {
  pushToast: (input: ToastInput) => void;
  confirm: (options: ConfirmOptions) => Promise<boolean>;
  prompt: (options: PromptOptions) => Promise<string | null>;
}

const FeedbackContext = createContext<FeedbackContextValue | null>(null);

const TOAST_TONE_CLASS: Record<ToastTone, string> = {
  success: "border-green-200 bg-green-50 text-green-900",
  error: "border-red-200 bg-red-50 text-red-900",
  info: "border-ink-200 bg-white text-ink-900",
};

export function FeedbackProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const [pendingConfirm, setPendingConfirm] = useState<PendingConfirm | null>(
    null,
  );
  const [pendingPrompt, setPendingPrompt] = useState<PendingPrompt | null>(null);
  const titleId = useId();
  const descId = useId();
  const promptTitleId = useId();
  const promptDescId = useId();

  const pushToast = useCallback((input: ToastInput) => {
    const id = crypto.randomUUID();
    setToasts((prev) => [...prev, { ...input, id }].slice(-5));
    const duration = input.durationMs ?? 5000;
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, duration);
  }, []);

  const confirm = useCallback((options: ConfirmOptions) => {
    return new Promise<boolean>((resolve) => {
      setPendingConfirm({ ...options, resolve });
    });
  }, []);

  const prompt = useCallback((options: PromptOptions) => {
    return new Promise<string | null>((resolve) => {
      setPendingPrompt({ ...options, resolve });
    });
  }, []);

  const closeConfirm = useCallback((accepted: boolean) => {
    setPendingConfirm((current) => {
      current?.resolve(accepted);
      return null;
    });
  }, []);

  const closePrompt = useCallback((value: string | null) => {
    setPendingPrompt((current) => {
      current?.resolve(value);
      return null;
    });
  }, []);

  useEffect(() => {
    if (!pendingConfirm) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeConfirm(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [pendingConfirm, closeConfirm]);

  useEffect(() => {
    if (!pendingPrompt) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") closePrompt(null);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [pendingPrompt, closePrompt]);

  const value = useMemo(
    () => ({ pushToast, confirm, prompt }),
    [pushToast, confirm, prompt],
  );

  return (
    <FeedbackContext.Provider value={value}>
      {children}
      <ToastViewport toasts={toasts} onDismiss={(id) => setToasts((t) => t.filter((x) => x.id !== id))} />
      {pendingConfirm && (
        <ConfirmDialog
          {...pendingConfirm}
          titleId={titleId}
          descId={descId}
          onCancel={() => closeConfirm(false)}
          onConfirm={() => closeConfirm(true)}
        />
      )}
      {pendingPrompt && (
        <PromptDialog
          {...pendingPrompt}
          titleId={promptTitleId}
          descId={promptDescId}
          onCancel={() => closePrompt(null)}
          onConfirm={(value) => closePrompt(value)}
        />
      )}
    </FeedbackContext.Provider>
  );
}

function ToastViewport({
  toasts,
  onDismiss,
}: {
  toasts: ToastItem[];
  onDismiss: (id: string) => void;
}) {
  if (toasts.length === 0) return null;
  return (
    <div
      className="pointer-events-none fixed right-4 top-4 z-[100] flex w-full max-w-sm flex-col gap-2"
      aria-live="polite"
      aria-relevant="additions"
    >
      {toasts.map((toast) => (
        <div
          key={toast.id}
          data-testid="toast"
          data-tone={toast.tone ?? "info"}
          className={`pointer-events-auto rounded-lg border px-4 py-3 shadow-lg ${TOAST_TONE_CLASS[toast.tone ?? "info"]}`}
        >
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="text-sm font-medium">{toast.title}</p>
              {toast.description && (
                <p className="mt-1 whitespace-pre-wrap text-xs opacity-90">
                  {toast.description}
                </p>
              )}
            </div>
            <button
              type="button"
              aria-label="Dismiss notification"
              onClick={() => onDismiss(toast.id)}
              className="shrink-0 rounded px-1 text-xs opacity-60 hover:opacity-100"
            >
              ×
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

function ConfirmDialog({
  title,
  message,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  tone = "default",
  titleId,
  descId,
  onCancel,
  onConfirm,
}: PendingConfirm & {
  titleId: string;
  descId: string;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const confirmRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    confirmRef.current?.focus();
  }, []);

  const confirmClass =
    tone === "danger"
      ? "bg-red-600 hover:bg-red-700"
      : "bg-accent-500 hover:bg-accent-600";

  return (
    <div
      className="fixed inset-0 z-[110] flex items-center justify-center bg-black/30 p-4"
      onClick={onCancel}
      data-testid="confirm-dialog-backdrop"
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descId}
        data-testid="confirm-dialog"
        className="w-full max-w-md rounded-lg border border-ink-200 bg-white p-5 shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id={titleId} className="text-sm font-semibold text-ink-900">
          {title}
        </h2>
        <p
          id={descId}
          className="mt-2 whitespace-pre-wrap text-sm text-ink-600"
        >
          {message}
        </p>
        <div className="mt-5 flex justify-end gap-2">
          <button
            type="button"
            data-testid="confirm-dialog-cancel"
            onClick={onCancel}
            className="rounded-md border border-ink-200 px-3 py-1.5 text-xs text-ink-700 hover:bg-ink-100"
          >
            {cancelLabel}
          </button>
          <button
            ref={confirmRef}
            type="button"
            data-testid="confirm-dialog-confirm"
            onClick={onConfirm}
            className={`rounded-md px-3 py-1.5 text-xs font-medium text-white ${confirmClass}`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

function PromptDialog({
  title,
  message,
  placeholder,
  defaultValue = "",
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  tone = "default",
  multiline = false,
  titleId,
  descId,
  onCancel,
  onConfirm,
}: PendingPrompt & {
  titleId: string;
  descId: string;
  onCancel: () => void;
  onConfirm: (value: string) => void;
}) {
  const [value, setValue] = useState(defaultValue);
  const inputRef = useRef<HTMLInputElement | HTMLTextAreaElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const confirmClass =
    tone === "danger"
      ? "bg-red-600 hover:bg-red-700"
      : "bg-accent-500 hover:bg-accent-600";

  const inputClass =
    "w-full rounded-md border border-ink-300 px-2 py-1.5 text-sm text-ink-900 focus:border-accent-500 focus:outline-none focus:ring-1 focus:ring-accent-500";

  return (
    <div
      className="fixed inset-0 z-[110] flex items-center justify-center bg-black/30 p-4"
      onClick={onCancel}
      data-testid="prompt-dialog-backdrop"
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={message ? descId : undefined}
        data-testid="prompt-dialog"
        className="w-full max-w-md rounded-lg border border-ink-200 bg-white p-5 shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id={titleId} className="text-sm font-semibold text-ink-900">
          {title}
        </h2>
        {message && (
          <p
            id={descId}
            className="mt-2 whitespace-pre-wrap text-sm text-ink-600"
          >
            {message}
          </p>
        )}
        <div className="mt-4">
          {multiline ? (
            <textarea
              ref={inputRef as RefObject<HTMLTextAreaElement>}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={placeholder}
              rows={3}
              data-testid="prompt-dialog-input"
              className={inputClass}
            />
          ) : (
            <input
              ref={inputRef as RefObject<HTMLInputElement>}
              type="text"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={placeholder}
              data-testid="prompt-dialog-input"
              className={inputClass}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  onConfirm(value);
                }
              }}
            />
          )}
        </div>
        <div className="mt-5 flex justify-end gap-2">
          <button
            type="button"
            data-testid="prompt-dialog-cancel"
            onClick={onCancel}
            className="rounded-md border border-ink-200 px-3 py-1.5 text-xs text-ink-700 hover:bg-ink-100"
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            data-testid="prompt-dialog-confirm"
            onClick={() => onConfirm(value)}
            className={`rounded-md px-3 py-1.5 text-xs font-medium text-white ${confirmClass}`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

function useFeedbackContext(): FeedbackContextValue {
  const ctx = useContext(FeedbackContext);
  if (!ctx) {
    throw new Error(
      "useToast/useConfirm/usePrompt must be used within FeedbackProvider",
    );
  }
  return ctx;
}

export function useToast() {
  const { pushToast } = useFeedbackContext();
  return pushToast;
}

export function useConfirm() {
  const { confirm } = useFeedbackContext();
  return confirm;
}

export function usePrompt() {
  const { prompt } = useFeedbackContext();
  return prompt;
}
