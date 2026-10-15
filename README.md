# KernAuth TypeScript example

Paste the public app ID from Developers into `index.ts`. Node.js 20 or newer.

## Start

```ts
const app = new KernAuth("https://api.kernauth.com", "__PUBLIC_APP_ID__");
```

Type the license at the prompt. `KERN_LICENSE_KEY` skips the prompt. The program checks that the key is valid and prints when it expires. It does not save a computer.

## Run

```
npm install -D vitest
npx vitest run typescript.test.ts
node --experimental-strip-types index.ts
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
