import { type SyntheticEvent, useCallback, useEffect, useState } from "react";

import { ApiError } from "../../lib/api";
import { type PolicyEvaluation, evaluatePolicy } from "../security/api";
import {
  type CataloguePreset,
  type CatalogueSoftware,
  type CommitResult,
  KIND_LABEL,
  KIND_SHORT,
  type PackageDraft,
  type SearchHit,
  commitDraft,
  discardDraft,
  inspectPreset,
  inspectUpload,
  inspectUrl,
  listAdminSoftware,
  listMyDevices,
  listPresets,
  searchCatalogue,
} from "./api";

function messageOf(error: unknown): string {
  return error instanceof ApiError ? error.message : "The service returned an unexpected response.";
}

export function CatalogueSearch() {
  const [query, setQuery] = useState("");
  const [hits, setHits] = useState<SearchHit[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [devices, setDevices] = useState<{ id: string; deviceName: string; status: string }[]>([]);
  const [deviceId, setDeviceId] = useState("");
  const [decision, setDecision] = useState<PolicyEvaluation | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    listMyDevices(controller.signal)
      .then((rows) => {
        setDevices(rows);
        const preferred = rows.find((d) => d.status === "ACTIVE") ?? rows[0];
        if (preferred) setDeviceId(preferred.id);
      })
      .catch(() => {
        /* employees without devices still search */
      });
    return () => {
      controller.abort();
    };
  }, []);

  const submit = (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setDecision(null);
    searchCatalogue(query.trim())
      .then(setHits)
      .catch((err: unknown) => {
        setError(messageOf(err));
        setHits(null);
      })
      .finally(() => {
        setBusy(false);
      });
  };

  const runPolicy = (versionId: string) => {
    if (!deviceId) {
      setError("Enroll a device before evaluating policy.");
      return;
    }
    setBusy(true);
    setError(null);
    evaluatePolicy(deviceId, versionId)
      .then(setDecision)
      .catch((err: unknown) => {
        setError(messageOf(err));
      })
      .finally(() => {
        setBusy(false);
      });
  };

  return (
    <section className="status-card" aria-labelledby="catalogue-search-title">
      <h2 id="catalogue-search-title">Catalogue</h2>
      <form className="login-form" onSubmit={submit}>
        <label>
          Search approved software
          <input
            type="search"
            value={query}
            maxLength={120}
            placeholder="e.g. Visual Studio Code"
            onChange={(e) => {
              setQuery(e.target.value);
            }}
          />
        </label>
        {devices.length > 0 && (
          <label>
            Device for policy check
            <select
              value={deviceId}
              onChange={(e) => {
                setDeviceId(e.target.value);
              }}
            >
              {devices.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.deviceName} ({d.status})
                </option>
              ))}
            </select>
          </label>
        )}
        <button type="submit" disabled={busy || !query.trim()}>
          {busy ? "Searching…" : "Search"}
        </button>
      </form>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {decision && (
        <p
          className={
            decision.outcome === "AUTO_APPROVE" || decision.outcome === "ALLOW"
              ? "notice"
              : "form-error"
          }
          role="status"
        >
          {decision.softwareSlug}: {decision.outcome}
          {decision.threatVerdict ? ` · threat ${decision.threatVerdict}` : ""} —{" "}
          {decision.publicMessage}
        </p>
      )}
      {hits && hits.length === 0 && <p className="muted">No approved catalogue match.</p>}
      {hits && hits.length > 0 && (
        <ul className="device-list">
          {hits.map((hit) => (
            <li key={hit.software.id}>
              <strong>{hit.software.displayName}</strong>{" "}
              <span className="muted">
                {hit.software.publisher} · {hit.software.riskLevel}
                {hit.matchedAlias ? ` · matched “${hit.matchedAlias}”` : ""}
              </span>
              <ul className="checks">
                {hit.activeVersions.map((v) => (
                  <li key={v.id}>
                    {v.version} · {v.osFamily}/{v.architecture}{" "}
                    <button
                      type="button"
                      disabled={busy || !deviceId}
                      onClick={() => {
                        runPolicy(v.id);
                      }}
                    >
                      Evaluate policy
                    </button>
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

type SourceTab = "preset" | "url" | "upload";

type WizardStep =
  | { name: "choose" }
  | { name: "inspecting"; label: string }
  | { name: "review"; draft: PackageDraft }
  | { name: "done"; result: CommitResult };

interface WizardError {
  message: string;
  hint: string | null;
}

function wizardError(error: unknown): WizardError {
  if (error instanceof ApiError) {
    return { message: error.message, hint: error.detail("hint") };
  }
  return { message: messageOf(error), hint: null };
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(0)} MB`;
  return `${Math.max(1, Math.round(bytes / 1024)).toFixed(0)} KB`;
}

const ARCH_LABEL: Record<string, string> = {
  universal: "Apple silicon + Intel",
  arm64: "Apple silicon",
  x86_64: "Intel",
};

function useElapsedSeconds(active: boolean): number {
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    if (!active) return;
    const started = Date.now();
    const timer = window.setInterval(() => {
      setSeconds(Math.floor((Date.now() - started) / 1000));
    }, 1000);
    return () => {
      window.clearInterval(timer);
      setSeconds(0);
    };
  }, [active]);
  return seconds;
}

function PresetGrid({
  presets,
  disabled,
  onPick,
}: {
  presets: CataloguePreset[] | null;
  disabled: boolean;
  onPick: (preset: CataloguePreset) => void;
}) {
  if (presets === null) return <p className="muted">Loading popular apps…</p>;
  if (presets.length === 0) return <p className="muted">No presets configured.</p>;
  return (
    <ul className="preset-grid">
      {presets.map((p) => (
        <li key={p.id}>
          <button
            type="button"
            className="preset-card"
            disabled={disabled}
            onClick={() => {
              onPick(p);
            }}
          >
            <span className="preset-name">{p.name}</span>
            <span className="preset-publisher">{p.publisher}</span>
            <span className="preset-meta">
              <span className="badge">{KIND_SHORT[p.kind]}</span>
              {p.inCatalogue && <span className="badge badge-ok">In catalogue</span>}
            </span>
          </button>
        </li>
      ))}
    </ul>
  );
}

function DraftReview({
  draft,
  busy,
  onCommit,
  onCancel,
}: {
  draft: PackageDraft;
  busy: boolean;
  onCommit: (displayName: string, aliases: string[], requireApproval: boolean) => void;
  onCancel: () => void;
}) {
  const [displayName, setDisplayName] = useState(draft.existingSoftware?.displayName ?? draft.name);
  const [aliases, setAliases] = useState(draft.suggestedAliases.join(", "));
  const [requireApproval, setRequireApproval] = useState(draft.requireApprovalDefault);
  const duplicate = draft.alreadyInCatalogue;

  return (
    <form
      className="login-form draft-review"
      onSubmit={(event) => {
        event.preventDefault();
        onCommit(
          displayName.trim(),
          aliases
            .split(",")
            .map((a) => a.trim())
            .filter(Boolean),
          requireApproval,
        );
      }}
    >
      <div className="draft-verified" role="status">
        <span className="badge badge-ok">Signature verified</span>
        <span>
          Signed by <strong>{draft.publisher}</strong> · Team ID <code>{draft.teamId}</code>
        </span>
      </div>
      <dl className="draft-facts">
        <div>
          <dt>Version</dt>
          <dd>{draft.version}</dd>
        </div>
        <div>
          <dt>Format</dt>
          <dd>{KIND_LABEL[draft.kind]}</dd>
        </div>
        <div>
          <dt>Runs on</dt>
          <dd>{ARCH_LABEL[draft.architecture] ?? draft.architecture}</dd>
        </div>
        <div>
          <dt>Needs macOS</dt>
          <dd>{draft.minimumOsVersion}+</dd>
        </div>
        <div>
          <dt>Size</dt>
          <dd>{formatBytes(draft.packageSizeBytes)}</dd>
        </div>
        <div>
          <dt>Identifier</dt>
          <dd>
            <code>{draft.identifier}</code>
          </dd>
        </div>
        {draft.payloadPath && (
          <div>
            <dt>Installs</dt>
            <dd>{draft.payloadPath}</dd>
          </div>
        )}
        <div>
          <dt>SHA-256</dt>
          <dd>
            <code title={draft.sha256}>{draft.sha256.slice(0, 16)}…</code>
          </dd>
        </div>
      </dl>
      {draft.warnings.map((w) => (
        <p key={w.code} className="notice">
          {w.hint}
        </p>
      ))}
      {draft.existingSoftware && !duplicate && (
        <p className="muted">
          Adds version {draft.version} to the existing “{draft.existingSoftware.displayName}” entry.
        </p>
      )}
      {duplicate ? (
        <p className="notice" role="status">
          Version {duplicate.version} is already in the catalogue with this exact file. Nothing to
          add.
        </p>
      ) : (
        <>
          <label>
            Name employees see
            <input
              required
              value={displayName}
              maxLength={120}
              disabled={Boolean(draft.existingSoftware)}
              onChange={(e) => {
                setDisplayName(e.target.value);
              }}
            />
          </label>
          <label>
            Other names people search for (comma-separated)
            <input
              value={aliases}
              maxLength={400}
              onChange={(e) => {
                setAliases(e.target.value);
              }}
            />
          </label>
          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={requireApproval}
              onChange={(e) => {
                setRequireApproval(e.target.checked);
              }}
            />{" "}
            Require approval before install
          </label>
        </>
      )}
      <div className="wizard-actions">
        {!duplicate && (
          <button type="submit" disabled={busy || !displayName.trim()}>
            {busy ? "Adding…" : "Add to catalogue"}
          </button>
        )}
        <button type="button" disabled={busy} onClick={onCancel}>
          {duplicate ? "Done" : "Cancel"}
        </button>
      </div>
    </form>
  );
}

export function AddSoftwareWizard({ onIngested }: { onIngested?: () => void }) {
  const [tab, setTab] = useState<SourceTab>("preset");
  const [step, setStep] = useState<WizardStep>({ name: "choose" });
  const [presets, setPresets] = useState<CataloguePreset[] | null>(null);
  const [sourceUrl, setSourceUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<WizardError | null>(null);
  const [busy, setBusy] = useState(false);
  const elapsed = useElapsedSeconds(step.name === "inspecting");

  const loadPresets = useCallback((signal?: AbortSignal) => {
    listPresets(signal)
      .then(setPresets)
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setPresets([]);
      });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    loadPresets(controller.signal);
    return () => {
      controller.abort();
    };
  }, [loadPresets]);

  const inspect = (label: string, run: () => Promise<PackageDraft>) => {
    setError(null);
    setStep({ name: "inspecting", label });
    run()
      .then((draft) => {
        setStep({ name: "review", draft });
      })
      .catch((err: unknown) => {
        setError(wizardError(err));
        setStep({ name: "choose" });
      });
  };

  const reset = () => {
    setStep({ name: "choose" });
    setError(null);
    setFile(null);
    setSourceUrl("");
  };

  const cancel = (draft: PackageDraft) => {
    discardDraft(draft.draftId).catch(() => {
      /* drafts expire on their own */
    });
    reset();
  };

  const commit = (
    draft: PackageDraft,
    displayName: string,
    aliases: string[],
    requireApproval: boolean,
  ) => {
    setBusy(true);
    setError(null);
    commitDraft({ draftId: draft.draftId, displayName, aliases, requireApproval })
      .then((result) => {
        setStep({ name: "done", result });
        loadPresets();
        onIngested?.();
      })
      .catch((err: unknown) => {
        setError(wizardError(err));
      })
      .finally(() => {
        setBusy(false);
      });
  };

  return (
    <section className="status-card" aria-labelledby="add-software-title">
      <h2 id="add-software-title">Add software</h2>
      {step.name === "choose" && (
        <>
          <p className="muted">
            Pick a popular app, paste a download link, or upload a .pkg, .dmg or .zip. SentinelDesk
            checks the signature and fills in the details for you.
          </p>
          <div className="segmented" role="tablist" aria-label="Package source">
            {(
              [
                ["preset", "Popular apps"],
                ["url", "Download link"],
                ["upload", "Upload file"],
              ] as const
            ).map(([id, label]) => (
              <button
                key={id}
                type="button"
                role="tab"
                aria-selected={tab === id}
                className={tab === id ? "segmented-active" : ""}
                onClick={() => {
                  setTab(id);
                  setError(null);
                }}
              >
                {label}
              </button>
            ))}
          </div>
          {tab === "preset" && (
            <PresetGrid
              presets={presets}
              disabled={false}
              onPick={(p) => {
                inspect(`Downloading ${p.name}`, () => inspectPreset(p.id));
              }}
            />
          )}
          {tab === "url" && (
            <form
              className="login-form"
              onSubmit={(event) => {
                event.preventDefault();
                const url = sourceUrl.trim();
                inspect("Downloading the package", () => inspectUrl(url));
              }}
            >
              <label>
                Download link (https)
                <input
                  type="url"
                  required
                  value={sourceUrl}
                  maxLength={2000}
                  placeholder="https://example.com/App.dmg"
                  onChange={(e) => {
                    setSourceUrl(e.target.value);
                  }}
                />
              </label>
              <button type="submit" disabled={!sourceUrl.trim().startsWith("https://")}>
                Check package
              </button>
            </form>
          )}
          {tab === "upload" && (
            <form
              className="login-form"
              onSubmit={(event) => {
                event.preventDefault();
                if (!file) return;
                inspect(`Uploading ${file.name}`, () => inspectUpload(file));
              }}
            >
              <label>
                Package file
                <input
                  type="file"
                  accept=".pkg,.dmg,.zip"
                  onChange={(e) => {
                    setFile(e.target.files?.[0] ?? null);
                  }}
                />
              </label>
              <button type="submit" disabled={!file}>
                Check package
              </button>
            </form>
          )}
        </>
      )}
      {step.name === "inspecting" && (
        <div className="install-activity install-activity-live" role="status" aria-live="polite">
          <p className="install-headline">{step.label}…</p>
          <div className="install-bar" aria-hidden="true">
            <span className="install-bar-fill" />
          </div>
          <p className="muted">
            {elapsed < 8
              ? "Fetching the file."
              : elapsed < 30
                ? "Opening it safely and checking the developer signature."
                : "Large apps take a minute or two. You can keep this tab open."}
          </p>
        </div>
      )}
      {step.name === "review" && (
        <DraftReview
          draft={step.draft}
          busy={busy}
          onCommit={(name, aliases, requireApproval) => {
            commit(step.draft, name, aliases, requireApproval);
          }}
          onCancel={() => {
            cancel(step.draft);
          }}
        />
      )}
      {step.name === "done" && (
        <div className="draft-done" role="status">
          <p className="notice">
            {step.result.status === "ADDED"
              ? `${step.result.displayName} ${step.result.version} is now in the catalogue.`
              : `${step.result.displayName} ${step.result.version} was already in the catalogue.`}{" "}
            Employees can ask for it by name.
          </p>
          <button type="button" onClick={reset}>
            Add another app
          </button>
        </div>
      )}
      {error && (
        <div className="form-error" role="alert">
          <p>{error.message}</p>
          {error.hint && <p className="error-hint">{error.hint}</p>}
        </div>
      )}
    </section>
  );
}

export function AdminCatalogue() {
  const [rows, setRows] = useState<CatalogueSoftware[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback((signal?: AbortSignal) => {
    listAdminSoftware(signal)
      .then(setRows)
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setError(messageOf(err));
      });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    reload(controller.signal);
    return () => {
      controller.abort();
    };
  }, [reload]);

  return (
    <>
      <AddSoftwareWizard
        onIngested={() => {
          reload();
        }}
      />
      <section className="status-card" aria-labelledby="admin-catalogue-title">
        <h2 id="admin-catalogue-title">Catalogue admin</h2>
        <p className="muted">
          Mac catalogue entries. Digests are pinned automatically on ingest so threat checks stay
          fail-closed.
        </p>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        {rows === null && !error && <p className="muted">Loading catalogue…</p>}
        {rows && rows.length === 0 && <p className="muted">No catalogue entries yet.</p>}
        {rows && rows.length > 0 && (
          <ul className="device-list">
            {rows.map((s) => (
              <li key={s.id}>
                <strong>{s.displayName}</strong>{" "}
                <span
                  className={`badge ${s.lifecycleStatus === "ACTIVE" ? "badge-ok" : "badge-bad"}`}
                >
                  {s.lifecycleStatus}
                </span>
                <span className="muted">
                  {" "}
                  {s.slug} · {s.publisher} · {s.riskLevel}
                </span>
              </li>
            ))}
          </ul>
        )}
        <button
          type="button"
          onClick={() => {
            reload();
          }}
        >
          Refresh
        </button>
      </section>
    </>
  );
}
