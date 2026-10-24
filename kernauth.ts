export function checkBody(appId: string, licenseKey: string, version = "1.0.0") {
  return {
    protocol_version: 1,
    public_app_id: appId,
    client_version: version || "1.0.0",
    license_key: licenseKey,
  };
}

export function apiMessage(payload: unknown, fallback: string): string {
  const message = (payload as { error?: { message?: unknown } } | null)?.error?.message;
  return typeof message === "string" && message !== "" ? message : fallback;
}

export class KernAuth {
  message = "";
  expiresAt: string | null = null;
  private readonly clientVersion: string;

  constructor(
    private readonly api: string,
    private readonly appId: string,
    version = "",
  ) {
    this.clientVersion = version || "1.0.0";
  }

  async check(licenseKey: string): Promise<boolean> {
    const response = await fetch(`${this.api}/v1/client/check`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(checkBody(this.appId, licenseKey, this.clientVersion)),
    });
    const payload: unknown = await response.json().catch(() => null);
    const valid = (payload as { valid?: unknown } | null)?.valid === true;
    if (!response.ok || !valid) {
      this.message = apiMessage(payload, `check failed (${response.status})`);
      this.expiresAt = null;
      return false;
    }
    const expires = (payload as { expires_at?: unknown }).expires_at;
    this.message = "License is active";
    this.expiresAt = typeof expires === "string" ? expires : null;
    return true;
  }
}
