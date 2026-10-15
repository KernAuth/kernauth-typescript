import { describe, expect, it } from "vitest";
import { apiMessage, checkBody } from "./kernauth";

describe("TypeScript check", () => {
  it("builds the check body and reads the API message", () => {
    expect(checkBody("pub_harbor_desktop", "KERN-ABCD-EFGH-IJKL-MNOP")).toEqual({
      protocol_version: 1,
      public_app_id: "pub_harbor_desktop",
      client_version: "1.0.0",
      license_key: "KERN-ABCD-EFGH-IJKL-MNOP",
    });
    expect(apiMessage({ error: { message: "Update required" } }, "no")).toBe("Update required");
    expect(apiMessage({}, "no")).toBe("no");
  });
});
