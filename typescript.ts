const API = "https://api.kernauth.com";
const APP_ID = "__PUBLIC_APP_ID__";
const PUBLIC_KEY = "__PUBLIC_KEY__";
declare const process: {
  argv: string[];
  env: Record<string, string | undefined>;
  platform: string;
  stdout: { write(value: string): void };
  stdin: { isTTY?: boolean };
  exit(code: number): never;
};

type EntitlementInfo = { status: string; features: string; license_id: string; expires_at: string };

export class KernAuth {
  success = false;
  message = "";
  entitlement: EntitlementInfo | null = null;

  constructor(
    readonly api = API,
    readonly appId = APP_ID,
    readonly publicKey = PUBLIC_KEY,
  ) {}

  validate(licenseKey: string, installationId: string) {
    return this.call("validate", licenseKey, installationId, "License is active");
  }

  private async call(
    mode: "validate",
    licenseKey: string,
    installationId: string,
    okMessage: string,
  ) {
    try {
      const ent = await request(mode, licenseKey, installationId, this.api, this.appId, this.publicKey);
      const features = ent.features;
      this.entitlement = {
        status: String(ent.status),
        features: canonicalJson(typeof features === "string" ? JSON.parse(features) : features),
        license_id: String(ent.license_id),
        expires_at: String(ent.expires_at),
      };
    } catch (error) {
      this.success = false;
      this.message = error instanceof Error ? error.message : "request failed";
      this.entitlement = null;
      return false;
    }
    this.success = true;
    this.message = okMessage;
    return true;
  }
}

type NodeFs = {
  existsSync(path: string): boolean;
  readFileSync(path: string, encoding: "utf8"): string;
  writeFileSync(path: string, data: string): void;
  readSync(fd: number, buffer: Uint8Array, offset: number, length: number, position: null): number;
};

async function nodeFs(): Promise<NodeFs> {
  const specifier = "node:fs";
  return await import(specifier) as NodeFs;
}

async function readLine(fs: NodeFs): Promise<string> {
  const buffer = new Uint8Array(4096);
  let text = "";
  while (!text.includes("\n")) {
    const count = fs.readSync(0, buffer, 0, buffer.length, null);
    if (count === 0) break;
    text += new TextDecoder().decode(buffer.subarray(0, count));
  }
  return text.split("\n")[0]?.trim() ?? "";
}

async function licenseKey(fs: NodeFs): Promise<string> {
  const fromEnv = process.env.KERN_LICENSE_KEY?.trim();
  if (fromEnv) return fromEnv;
  if (process.stdin.isTTY) process.stdout.write("Enter license: ");
  return readLine(fs);
}

function acceptableHwid(value: string): boolean {
  return /^[A-Za-z0-9_-]{8,64}$/.test(value);
}

async function machineHwid(fs: NodeFs): Promise<string> {
  const childProcess = await new Function("return import('node:child_process')")() as {
    execFileSync(file: string, args: string[], options: { encoding: "utf8" }): string;
  };
  if (process.platform === "win32") {
    return childProcess.execFileSync("powershell.exe", ["-NoProfile", "-Command", "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"], { encoding: "utf8" });
  }
  if (process.platform === "darwin") {
    const output = childProcess.execFileSync("ioreg", ["-rd1", "-c", "IOPlatformExpertDevice"], { encoding: "utf8" });
    return output.match(/"IOPlatformUUID" = "([^"]+)"/)?.[1] ?? "";
  }
  return fs.readFileSync("/etc/machine-id", "utf8");
}

async function installationId(fs: NodeFs): Promise<string> {
  const fromEnv = process.env.KERN_INSTALLATION_ID?.trim();
  if (fromEnv) return fromEnv;
  const hwid = (await machineHwid(fs)).trim();
  if (acceptableHwid(hwid)) return hwid;
  throw new Error("Could not read the HWID");
}

if (process.argv[1]?.endsWith("typescript.ts")) {
  const fs = await nodeFs();
  const key = await licenseKey(fs);
  const hwid = await installationId(fs);
  const app = new KernAuth(API, APP_ID, PUBLIC_KEY);
  if (!await app.validate(key, hwid)) {
    throw new Error(app.message);
  }
  const ent = app.entitlement;
  if (ent === null) throw new Error(app.message);
  process.stdout.write(`Status: ${ent.status}\n`);
  process.stdout.write(`Features: ${ent.features}\n`);
  process.stdout.write(`License: ${ent.license_id}\n`);
  process.stdout.write(`Check expires: ${ent.expires_at}\n`);
  for (;;) {
    await new Promise((resolve) => setTimeout(resolve, 60_000));
    try {
      await heartbeat(key, hwid, API, APP_ID);
    } catch (error) {
      process.stdout.write(`${error instanceof Error ? error.message : "heartbeat failed"}\n`);
      process.exit(1);
    }
  }
}

const fields = ["protocol_version", "entitlement_id", "application_id", "license_id", "status",
  "features", "device_id", "issued_at", "expires_at", "server_time", "nonce", "key_id"] as const;

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function canonical(entitlement: Record<string, unknown>): Uint8Array {
  const lines = fields.map((field) => {
    const value = field === "features"
      ? canonicalJson(typeof entitlement.features === "string" ? JSON.parse(entitlement.features) : entitlement.features)
      : String(entitlement[field]);
    if (value.includes("\n") || value.includes("\r")) throw new Error("Invalid entitlement field");
    return `${field}=${value}`;
  });
  return new TextEncoder().encode(`${lines.join("\n")}\n`);
}

function fromBase64(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) return null;
  try {
    return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

export async function verifyGrant(
  response: { entitlement: Record<string, unknown>; signature: string },
  nonce: string,
  appId = APP_ID,
  publicKey = PUBLIC_KEY,
  now = Date.now(),
): Promise<boolean> {
  const ent = response.entitlement;
  if (ent.protocol_version !== 1 || ent.nonce !== nonce || ent.application_id !== appId ||
      ent.status !== "active" ||
      typeof ent.expires_at !== "string" || Date.parse(ent.expires_at) <= now) return false;
  const keyBytes = fromBase64(publicKey);
  const signature = fromBase64(response.signature);
  if (keyBytes === null || keyBytes.length !== 32 || signature === null || signature.length !== 64) return false;
  const key = await crypto.subtle.importKey("raw", keyBytes.buffer as ArrayBuffer, "Ed25519", false, ["verify"]);
  return crypto.subtle.verify("Ed25519", key, signature.buffer as ArrayBuffer, canonical(ent).buffer as ArrayBuffer);
}

async function failureMessage(response: Response, fallback: string): Promise<string> {
  const failure = await response.json().catch(() => null) as { error?: { message?: string } } | null;
  const message = failure?.error?.message;
  return typeof message === "string" && message !== "" ? message : fallback;
}

async function heartbeat(licenseKey: string, installationId: string, api: string, appId: string): Promise<void> {
  const nonce = crypto.randomUUID().replaceAll("-", "");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`kernauth-device-v1:${installationId}`));
  const fingerprint = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  const response = await fetch(`${api}/v1/client/heartbeat`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ protocol_version: 1, public_app_id: appId, client_version: "1.0.0",
      license_key: licenseKey, fingerprint_version: 1, device_fingerprint: fingerprint,
      installation_id: installationId, nonce }),
  });
  if (!response.ok) throw new Error(await failureMessage(response, `heartbeat failed (${response.status})`));
  const payload = await response.json().catch(() => null) as { ok?: boolean } | null;
  if (payload?.ok !== true) throw new Error("heartbeat failed");
}

async function request(
  mode: "validate",
  licenseKey: string,
  installationId: string,
  api = API,
  appId = APP_ID,
  publicKey = PUBLIC_KEY,
) {
  const nonce = crypto.randomUUID().replaceAll("-", "");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`kernauth-device-v1:${installationId}`));
  const fingerprint = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  const response = await fetch(`${api}/v1/client/${mode}`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ protocol_version: 1, public_app_id: appId, client_version: "1.0.0",
      license_key: licenseKey, fingerprint_version: 1, device_fingerprint: fingerprint,
      installation_id: installationId, nonce }),
  });
  if (!response.ok) throw new Error(await failureMessage(response, `KernAuth ${mode} failed (${response.status})`));
  const body = await response.json() as { entitlement: Record<string, unknown>; signature: string };
  if (!await verifyGrant(body, nonce, appId, publicKey)) throw new Error("Invalid or expired signed entitlement");
  return body.entitlement;
}
