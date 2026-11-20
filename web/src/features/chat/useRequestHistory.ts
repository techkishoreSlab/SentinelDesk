import { useCallback, useEffect, useState } from "react";

import { ApiError } from "../../lib/api";
import { type SoftwareRequest, listMyRequests } from "../requests/api";

function messageOf(error: unknown): string {
  return error instanceof ApiError ? error.message : "The service returned an unexpected response.";
}

export function useRequestHistory(enabled: boolean) {
  const [history, setHistory] = useState<SoftwareRequest[]>([]);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(
    (signal?: AbortSignal) => {
      if (!enabled) return;
      listMyRequests(signal)
        .then(setHistory)
        .catch((err: unknown) => {
          if (err instanceof DOMException && err.name === "AbortError") return;
          setError(messageOf(err));
        });
    },
    [enabled],
  );

  useEffect(() => {
    const controller = new AbortController();
    reload(controller.signal);
    return () => {
      controller.abort();
    };
  }, [reload]);

  return { history, setHistory, error, reload };
}
