import { AsyncLocalStorage } from "node:async_hooks";

/** Runtime-owned budget, never populated from provider input or identity-token wire claims. */
export interface RequestProcessingContext {
  processingDeadlineMs?: number;
  requestSignal?: AbortSignal;
}

const processing = new AsyncLocalStorage<Readonly<RequestProcessingContext>>();

export function withRequestProcessing<T>(context: Readonly<RequestProcessingContext>, work: () => T): T {
  return processing.run(context, work);
}

export function getRequestProcessing(): Readonly<RequestProcessingContext> | undefined {
  return processing.getStore();
}
/** Capture the active request budget when verified authority escapes into a scoped service. */
export function captureRequestProcessing<T extends RequestProcessingContext>(value: Readonly<T>): Readonly<T> {
  const active = processing.getStore();
  return active ? Object.freeze({ ...value, ...active }) : value;
}


export function getRequestSignal(context?: Readonly<RequestProcessingContext>): AbortSignal | undefined {
  return context?.requestSignal ?? processing.getStore()?.requestSignal;
}

export function remainingProcessingMs(context?: Readonly<RequestProcessingContext>): number | undefined {
  getRequestSignal(context)?.throwIfAborted();
  const deadline = context?.processingDeadlineMs ?? processing.getStore()?.processingDeadlineMs;
  if (deadline === undefined) return undefined;
  const remaining = deadline - Date.now();
  if (!Number.isSafeInteger(deadline) || remaining <= 0) throw new DOMException("Connector request deadline expired", "TimeoutError");
  return Math.max(1, Math.floor(remaining));
}

export function assertProcessingActive(context?: Readonly<RequestProcessingContext>): void {
  remainingProcessingMs(context);
}

/** Stop a caller's wait without cancelling shared work; optionally handle its late result. */
export function waitForSignal<T>(
  pending: Promise<T>,
  signal: AbortSignal | undefined,
  onLate?: (value: T) => void,
): Promise<T> {
  if (!signal) return pending;
  return new Promise<T>((resolve, reject) => {
    let cancelled = false;
    const abort = (): void => {
      cancelled = true;
      reject(signal.reason);
    };
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
    void pending.then(
      (value) => {
        signal.removeEventListener("abort", abort);
        if (cancelled) onLate?.(value);
        else resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", abort);
        reject(error);
      },
    );
  });
}
