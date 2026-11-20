import { type SyntheticEvent, useCallback, useEffect, useState } from "react";

import { ApiError } from "../../lib/api";
import { type PolicyEvaluation, evaluatePolicy } from "../security/api";
import {
  type CatalogueSoftware,
  type IngestResult,
  type SearchHit,
  ingestCataloguePackage,
  listAdminSoftware,
  listMyDevices,
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

export function AddSoftwareWizard({ onIngested }: { onIngested?: () => void }) {
  const [mode, setMode] = useState<"url" | "upload">("url");
  const [slug, setSlug] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [publisher, setPublisher] = useState("");
  const [version, setVersion] = useState("");
  const [packageId, setPackageId] = useState("");
  const [aliases, setAliases] = useState("");
  const [architecture, setArchitecture] = useState("x86_64");
  const [sourceUrl, setSourceUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [requireApproval, setRequireApproval] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<IngestResult | null>(null);

  const submit = (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setResult(null);
    const form = new FormData();
    form.set("slug", slug.trim());
    form.set("display_name", displayName.trim());
    form.set("publisher", publisher.trim());
    form.set("version", version.trim());
    form.set("package_identifier", packageId.trim());
    form.set("aliases", aliases.trim());
    form.set("architecture", architecture);
    form.set("minimum_os_version", "12.0");
    form.set("require_approval", requireApproval ? "true" : "false");
    if (mode === "url") {
      form.set("source_url", sourceUrl.trim());
    } else if (file) {
      form.set("package", file);
    }
    ingestCataloguePackage(form)
      .then((row) => {
        setResult(row);
        onIngested?.();
      })
      .catch((err: unknown) => {
        setError(messageOf(err));
      })
      .finally(() => {
        setBusy(false);
      });
  };

  return (
    <section className="status-card" aria-labelledby="add-software-title">
      <h2 id="add-software-title">Add software</h2>
      <p className="muted">
        Upload a macOS .pkg or paste an https URL. SHA-256 and size are computed automatically.
        Production default keeps installs on require-approval (recommended for Go / gh / CLI tools).
      </p>
      <form className="login-form" onSubmit={submit}>
        <fieldset className="ingest-mode">
          <legend>Package source</legend>
          <label>
            <input
              type="radio"
              name="ingest-mode"
              checked={mode === "url"}
              onChange={() => {
                setMode("url");
              }}
            />{" "}
            HTTPS URL
          </label>
          <label>
            <input
              type="radio"
              name="ingest-mode"
              checked={mode === "upload"}
              onChange={() => {
                setMode("upload");
              }}
            />{" "}
            Upload .pkg
          </label>
        </fieldset>
        {mode === "url" ? (
          <label>
            Package URL
            <input
              type="url"
              required
              value={sourceUrl}
              placeholder="https://…/tool.pkg"
              onChange={(e) => {
                setSourceUrl(e.target.value);
              }}
            />
          </label>
        ) : (
          <label>
            Package file
            <input
              type="file"
              accept=".pkg,application/octet-stream"
              required
              onChange={(e) => {
                setFile(e.target.files?.[0] ?? null);
              }}
            />
          </label>
        )}
        <label>
          Slug
          <input
            required
            value={slug}
            maxLength={64}
            placeholder="go"
            onChange={(e) => {
              setSlug(e.target.value);
            }}
          />
        </label>
        <label>
          Display name
          <input
            required
            value={displayName}
            maxLength={120}
            placeholder="Go"
            onChange={(e) => {
              setDisplayName(e.target.value);
            }}
          />
        </label>
        <label>
          Publisher
          <input
            required
            value={publisher}
            maxLength={120}
            placeholder="Google LLC"
            onChange={(e) => {
              setPublisher(e.target.value);
            }}
          />
        </label>
        <label>
          Version
          <input
            required
            value={version}
            maxLength={40}
            placeholder="1.25.4"
            onChange={(e) => {
              setVersion(e.target.value);
            }}
          />
        </label>
        <label>
          Package identifier
          <input
            required
            value={packageId}
            maxLength={200}
            placeholder="org.golang.go"
            onChange={(e) => {
              setPackageId(e.target.value);
            }}
          />
        </label>
        <label>
          Aliases (comma-separated)
          <input
            value={aliases}
            maxLength={200}
            placeholder="golang, go lang"
            onChange={(e) => {
              setAliases(e.target.value);
            }}
          />
        </label>
        <label>
          Architecture
          <select
            value={architecture}
            onChange={(e) => {
              setArchitecture(e.target.value);
            }}
          >
            <option value="x86_64">x86_64</option>
            <option value="arm64">arm64</option>
            <option value="universal">universal</option>
          </select>
        </label>
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={requireApproval}
            onChange={(e) => {
              setRequireApproval(e.target.checked);
            }}
          />{" "}
          Require approval before install (recommended)
        </label>
        <button type="submit" disabled={busy || (mode === "upload" && !file)}>
          {busy ? "Ingesting…" : "Add to catalogue"}
        </button>
      </form>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {result && (
        <p className="notice" role="status">
          Added {result.displayName} · {result.filename} · sha256 {result.sha256.slice(0, 12)}… ·{" "}
          {result.policy} · staged at {result.stagedPath}
        </p>
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
