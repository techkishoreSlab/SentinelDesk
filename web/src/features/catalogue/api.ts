import { apiFormPost, apiGet, apiPost, isRecord } from "../../lib/api";

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
