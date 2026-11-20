import { SystemStatus } from "../features/health/SystemStatus";
import { SessionPanel } from "../features/session/SessionPanel";

export function App() {
  return (
    <div className="shell">
      <SessionPanel statusSlot={<SystemStatus />} />
    </div>
  );
}
