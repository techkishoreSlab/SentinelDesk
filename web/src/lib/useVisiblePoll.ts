import { useEffect, useRef } from "react";

/** Run `tick` immediately and every `intervalMs` while the document is visible. */
export function useVisiblePoll(tick: () => void, intervalMs: number, enabled: boolean): void {
  const tickRef = useRef(tick);
  useEffect(() => {
    tickRef.current = tick;
  }, [tick]);

  useEffect(() => {
    if (!enabled) return;

    let timer: number | null = null;

    const clear = () => {
      if (timer !== null) {
        window.clearInterval(timer);
        timer = null;
      }
    };

    const start = () => {
      clear();
      tickRef.current();
      timer = window.setInterval(() => {
        if (document.visibilityState === "visible") tickRef.current();
      }, intervalMs);
    };

    const onVisibility = () => {
      if (document.visibilityState === "visible") start();
      else clear();
    };

    if (document.visibilityState === "visible") start();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      clear();
    };
  }, [enabled, intervalMs]);
}
