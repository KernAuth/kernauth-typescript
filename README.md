# KernAuth TypeScript example

Paste the public app ID and public key from Developers into `typescript.ts`. Node.js 24 or newer.

## Instance

```ts
const app = new KernAuth(
  "https://api.kernauth.com",
  "__PUBLIC_APP_ID__",
  "__PUBLIC_KEY__",
);
```

## Validate

```ts
if (!await app.validate(licenseKey, installationId)) {
  throw new Error(app.message);
}
console.log(`Status: ${app.entitlement.status}`);
console.log(`Features: ${app.entitlement.features}`);
console.log(`License: ${app.entitlement.license_id}`);
console.log(`Check expires: ${app.entitlement.expires_at}`);
```

A good check prints the status, the feature flags stored on the license, the license id, and when this check expires. Type the license key at the prompt. `KERN_LICENSE_KEY` skips the prompt. The program reads the HWID from the computer. On Windows that is the signed-in user's SID. `KERN_INSTALLATION_ID` overrides that HWID.

## Run

```
npm install -D vitest
npx vitest run typescript.test.ts
node typescript.ts
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
