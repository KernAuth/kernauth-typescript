import { describe, expect, it } from "vitest";
import vectors from "./vectors.json";
import { canonical, verifyGrant } from "./typescript";

describe("TypeScript protocol example", () => {
  for (const vector of vectors.vectors) {
    it(`verifies Worker vector ${vector.name} and rejects tampering`, async () => {
      expect(new TextDecoder().decode(canonical(vector.fields))).toBe(vector.canonical);
      const grant = { entitlement: vector.fields, signature: vector.signature };
      const now = Date.parse("2026-01-01T00:01:00.000Z");
      expect(await verifyGrant(grant, vector.fields.nonce, vector.fields.application_id,
        vector.fields.key_id, vector.public_key, now)).toBe(true);
      expect(await verifyGrant(grant, "nonce_wrong", vector.fields.application_id,
        vector.fields.key_id, vector.public_key, now)).toBe(false);
      expect(await verifyGrant(grant, vector.fields.nonce, "pub_other_app",
        vector.fields.key_id, vector.public_key, now)).toBe(false);
      expect(await verifyGrant(grant, vector.fields.nonce, vector.fields.application_id,
        "wrong-key", vector.public_key, now)).toBe(false);
      expect(await verifyGrant(grant, vector.fields.nonce, vector.fields.application_id,
        vector.fields.key_id, vector.public_key, Date.parse(vector.fields.expires_at))).toBe(false);
      expect(await verifyGrant({ ...grant, signature: `${vector.signature}AA` }, vector.fields.nonce,
        vector.fields.application_id, vector.fields.key_id, vector.public_key, now)).toBe(false);
      expect(await verifyGrant({ ...grant, entitlement: { ...vector.fields, status: "revoked" } },
        vector.fields.nonce, vector.fields.application_id, vector.fields.key_id, vector.public_key, now)).toBe(false);
      expect(await verifyGrant({ ...grant, entitlement: { ...vector.fields, device_id: "tampered" } },
        vector.fields.nonce, vector.fields.application_id, vector.fields.key_id, vector.public_key, now)).toBe(false);
    });
  }
});
