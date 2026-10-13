# KernAuth TypeScript example

Protocol example for Node.js 24+. This is not the official SDK. The official client is the C++ SDK. This file calls the same activate, validate, and deactivate routes and checks the Ed25519 signature in Node.

## Add it

Paste the public app ID, key ID, and public key from Developers over the placeholders in `typescript.ts`.

```
npm install -D vitest
npx vitest run typescript.test.ts
```

Run the example with `KERN_LICENSE_KEY` and `KERN_INSTALLATION_ID` set. Persist one installation ID per device.

## Instance

```ts
const app = new KernAuth(
  "https://api.kernauth.com",
  "__PUBLIC_APP_ID__",
  "__KEY_ID__",
  "__PUBLIC_KEY__",
);
```

## Activate

```ts
if (!await app.activate(licenseKey, installationId)) {
  throw new Error(app.message);
}
```

## Validate

```ts
if (!await app.validate(licenseKey, installationId)) {
  throw new Error(app.message);
}
```

## Deactivate

```ts
if (!await app.deactivate(licenseKey, installationId)) {
  throw new Error(app.message);
}
```

`app.message` is `Device deactivated` after a successful deactivate.

A patched program can still skip the check. These examples do not add anti-debug or anti-VM code.

Documentation: https://kernauth.apidog.io
