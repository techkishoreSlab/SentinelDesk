import { apiBlobPost, apiDelete, apiFormPost, apiGet, apiPost, isRecord } from "../../lib/api";

export interface CatalogueSoftware {
  id: string;
  slug: string;
  displayName: string;
  description: string;
  publisher: string;
  category: string;
  lifecycleStatus: string;
  riskLevel: string;
  aliases: string[];
}

export interface CatalogueVersion {
  id: string;
  softwareId: string;
  version: string;
  osFamily: string;
  architecture: string;
  releaseStatus: string;
  metadataComplete: boolean;
  packageIdentifier: string | null;
}

export interface SearchHit {
  software: CatalogueSoftware;
  matchedAlias: string | null;
  activeVersions: CatalogueVersion[];
}

export interface CompatibilityResult {
  compatible: boolean;
  reasonCode: string;
  softwareDisplayName: string;
  version: string;
}

function str(value: unknown, field: string): string {
  if (typeof value !== "string") throw new TypeError(`invalid ${field}`);
  return value;
}

function optStr(value: unknown, field: string): string | null {
  return value === null ? null : str(value, field);
}

function list(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new TypeError("expected array");
  return value;
}

export function parseSoftware(value: unknown): CatalogueSoftware {
  if (!isRecord(value)) throw new TypeError("invalid software");
  return {
    id: str(value["id"], "id"),
    slug: str(value["slug"], "slug"),
    displayName: str(value["display_name"], "display_name"),
    description: str(value["description"], "description"),
    publisher: str(value["publisher"], "publisher"),
    category: str(value["category"], "category"),
    lifecycleStatus: str(value["lifecycle_status"], "lifecycle_status"),
    riskLevel: str(value["risk_level"], "risk_level"),
    aliases: list(value["aliases"]).map((a) => str(a, "alias")),
  };
}

export function parseVersion(value: unknown): CatalogueVersion {
  if (!isRecord(value)) throw new TypeError("invalid version");
  return {
    id: str(value["id"], "id"),
    softwareId: str(value["software_id"], "software_id"),
    version: str(value["version"], "version"),
    osFamily: str(value["os_family"], "os_family"),
    architecture: str(value["architecture"], "architecture"),
    releaseStatus: str(value["release_status"], "release_status"),
    metadataComplete: value["metadata_complete"] === true,
    packageIdentifier: optStr(value["package_identifier"], "package_identifier"),
  };
}

export function parseSearchHit(value: unknown): SearchHit {
  if (!isRecord(value)) throw new TypeError("invalid search hit");
  return {
    software: parseSoftware(value["software"]),
    matchedAlias: optStr(value["matched_alias"], "matched_alias"),
    activeVersions: list(value["active_versions"]).map(parseVersion),
  };
}

export function parseCompatibility(value: unknown): CompatibilityResult {
  if (!isRecord(value)) throw new TypeError("invalid compatibility");
  return {
    compatible: value["compatible"] === true,
    reasonCode: str(value["reason_code"], "reason_code"),
    softwareDisplayName: str(value["software_display_name"], "software_display_name"),
    version: str(value["version"], "version"),
  };
}

export const searchCatalogue = (q: string, signal?: AbortSignal) =>
  apiGet(
    `/api/v1/catalogue/search?q=${encodeURIComponent(q)}`,
    (v) => list(v).map(parseSearchHit),
    signal,
  );

export const listAdminSoftware = (signal?: AbortSignal) =>
  apiGet("/api/v1/admin/catalogue/software", (v) => list(v).map(parseSoftware), signal);

export const listMyDevices = (signal?: AbortSignal) =>
  apiGet(
    "/api/v1/devices",
    (v) =>
      list(v).map((item) => {
        if (!isRecord(item)) throw new TypeError("invalid device");
        return {
          id: str(item["id"], "id"),
          deviceName: str(item["device_name"], "device_name"),
          status: str(item["device_status"], "device_status"),
        };
      }),
    signal,
  );

export const checkCompatibility = (deviceId: string, catalogueVersionId: string) =>
  apiPost("/api/v1/catalogue/compatibility", parseCompatibility, {
    device_id: deviceId,
    catalogue_version_id: catalogueVersionId,
  });

export interface IngestResult {
  slug: string;
  displayName: string;
  sha256: string;
  packageSizeBytes: number;
  filename: string;
  stagedPath: string;
  policy: string;
  softwareId: string;
}

export function parseIngestResult(value: unknown): IngestResult {
  if (!isRecord(value)) throw new TypeError("invalid ingest result");
  const size = value["package_size_bytes"];
  if (typeof size !== "number") throw new TypeError("invalid package_size_bytes");
  return {
    slug: str(value["slug"], "slug"),
    displayName: str(value["display_name"], "display_name"),
    sha256: str(value["sha256"], "sha256"),
    packageSizeBytes: size,
    filename: str(value["filename"], "filename"),
    stagedPath: str(value["staged_path"], "staged_path"),
    policy: str(value["policy"], "policy"),
    softwareId: str(value["software_id"], "software_id"),
  };
}

export const ingestCataloguePackage = (form: FormData) =>
  apiFormPost("/api/v1/admin/catalogue/ingest", parseIngestResult, form);

export type InstallerKind = "MACOS_PKG" | "MACOS_DMG_APP" | "MACOS_DMG_PKG" | "MACOS_ZIP_APP";

export const KIND_LABEL: Record<InstallerKind, string> = {
  MACOS_PKG: "Installer package (.pkg)",
  MACOS_DMG_APP: "Disk image with app (.dmg)",
  MACOS_DMG_PKG: "Disk image with installer (.dmg)",
  MACOS_ZIP_APP: "Zipped app (.zip)",
};

export const KIND_SHORT: Record<InstallerKind, string> = {
  MACOS_PKG: "PKG",
  MACOS_DMG_APP: "DMG",
  MACOS_DMG_PKG: "DMG",
  MACOS_ZIP_APP: "ZIP",
};

function kind(value: unknown): InstallerKind {
  if (typeof value === "string" && value in KIND_LABEL) return value as InstallerKind;
  throw new TypeError("invalid kind");
}

function num(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new TypeError(`invalid ${field}`);
  return value;
}

export interface CataloguePreset {
  id: string;
  name: string;
  publisher: string;
  category: string;
  kind: InstallerKind;
  teamId: string;
  description: string;
  inCatalogue: boolean;
}

export function parsePreset(value: unknown): CataloguePreset {
  if (!isRecord(value)) throw new TypeError("invalid preset");
  return {
    id: str(value["id"], "id"),
    name: str(value["name"], "name"),
    publisher: str(value["publisher"], "publisher"),
    category: str(value["category"], "category"),
    kind: kind(value["kind"]),
    teamId: str(value["team_id"], "team_id"),
    description: str(value["description"], "description"),
    inCatalogue: value["in_catalogue"] === true,
  };
}

export interface DraftWarning {
  code: string;
  hint: string;
}

export interface PackageDraft {
  draftId: string;
  expiresAt: number;
  kind: InstallerKind;
  name: string;
  version: string;
  identifier: string;
  architecture: string;
  minimumOsVersion: string;
  teamId: string;
  publisher: string;
  signer: string;
  payloadPath: string | null;
  packageSizeBytes: number;
  sha256: string;
  suggestedSlug: string;
  suggestedAliases: string[];
  requireApprovalDefault: boolean;
  existingSoftware: { id: string; slug: string; displayName: string } | null;
  alreadyInCatalogue: { versionId: string; version: string } | null;
  warnings: DraftWarning[];
  presetId: string | null;
}

export function parseDraft(value: unknown): PackageDraft {
  if (!isRecord(value)) throw new TypeError("invalid draft");
  const existing = value["existing_software"];
  const already = value["already_in_catalogue"];
  return {
    draftId: str(value["draft_id"], "draft_id"),
    expiresAt: num(value["expires_at"], "expires_at"),
    kind: kind(value["kind"]),
    name: str(value["name"], "name"),
    version: str(value["version"], "version"),
    identifier: str(value["identifier"], "identifier"),
    architecture: str(value["architecture"], "architecture"),
    minimumOsVersion: str(value["minimum_os_version"], "minimum_os_version"),
    teamId: str(value["team_id"], "team_id"),
    publisher: str(value["publisher"], "publisher"),
    signer: str(value["signer"], "signer"),
    payloadPath: optStr(value["payload_path"] ?? null, "payload_path"),
    packageSizeBytes: num(value["package_size_bytes"], "package_size_bytes"),
    sha256: str(value["sha256"], "sha256"),
    suggestedSlug: str(value["suggested_slug"], "suggested_slug"),
    suggestedAliases: list(value["suggested_aliases"]).map((a) => str(a, "alias")),
    requireApprovalDefault: value["require_approval_default"] !== false,
    existingSoftware: isRecord(existing)
      ? {
          id: str(existing["id"], "id"),
          slug: str(existing["slug"], "slug"),
          displayName: str(existing["display_name"], "display_name"),
        }
      : null,
    alreadyInCatalogue: isRecord(already)
      ? {
          versionId: str(already["version_id"], "version_id"),
          version: str(already["version"], "version"),
        }
      : null,
    warnings: list(value["warnings"]).map((w) => {
      if (!isRecord(w)) throw new TypeError("invalid warning");
      return { code: str(w["code"], "code"), hint: str(w["hint"], "hint") };
    }),
    presetId: optStr(value["preset_id"] ?? null, "preset_id"),
  };
}

export interface CommitResult {
  status: "ADDED" | "ALREADY_IN_CATALOGUE";
  softwareId: string;
  slug: string;
  displayName: string;
  version: string;
  policy: string;
}

export function parseCommitResult(value: unknown): CommitResult {
  if (!isRecord(value)) throw new TypeError("invalid commit result");
  const status = value["status"];
  if (status !== "ADDED" && status !== "ALREADY_IN_CATALOGUE") {
    throw new TypeError("invalid status");
  }
  const version = value["version"];
  if (!isRecord(version)) throw new TypeError("invalid version");
  return {
    status,
    softwareId: str(value["software_id"], "software_id"),
    slug: str(value["slug"], "slug"),
    displayName: str(value["display_name"], "display_name"),
    version: str(version["version"], "version"),
    policy: str(value["policy"], "policy"),
  };
}

const ADMIN = "/api/v1/admin/catalogue";

export const listPresets = (signal?: AbortSignal) =>
  apiGet(`${ADMIN}/presets`, (v) => list(v).map(parsePreset), signal);

export const inspectPreset = (presetId: string) =>
  apiPost(`${ADMIN}/inspect`, parseDraft, { preset_id: presetId });

export const inspectUrl = (sourceUrl: string) =>
  apiPost(`${ADMIN}/inspect`, parseDraft, { source_url: sourceUrl });

export const inspectUpload = (file: File, signal?: AbortSignal) =>
  apiBlobPost(
    `${ADMIN}/inspect/upload?filename=${encodeURIComponent(file.name)}`,
    parseDraft,
    file,
    signal,
  );

export const discardDraft = (draftId: string) =>
  apiDelete(`${ADMIN}/drafts/${encodeURIComponent(draftId)}`);

export const commitDraft = (body: {
  draftId: string;
  displayName: string;
  aliases: string[];
  requireApproval: boolean;
}) =>
  apiPost(`${ADMIN}/commit`, parseCommitResult, {
    draft_id: body.draftId,
    display_name: body.displayName,
    aliases: body.aliases,
    require_approval: body.requireApproval,
  });
