import { KernAuth } from "./kernauth";

declare const process: {
  env: { KERN_LICENSE_KEY?: string };
  stdin: { isTTY?: boolean };
  stdout: { write(text: string): void };
  exit(code: number): never;
};
declare const console: { log(text: string): void };

type Reader = { readSync(fd: number, buffer: Uint8Array, offset: number, length: number, position: null): number };

const app = new KernAuth("https://api.kernauth.com", "__PUBLIC_APP_ID__");

function licenseKey(): string {
  const fromEnv = process.env.KERN_LICENSE_KEY?.trim();
  if (fromEnv) return fromEnv;
  if (process.stdin.isTTY) process.stdout.write("Enter license: ");
  const fs = (new Function("return require('node:fs')") as () => Reader)();
  const buffer = new Uint8Array(256);
  let text = "";
  for (;;) {
    const count = fs.readSync(0, buffer, 0, buffer.length, null);
    if (count === 0) break;
    text += new TextDecoder().decode(buffer.subarray(0, count));
    if (text.includes("\n")) break;
  }
  return text.split("\n")[0]?.trim() ?? "";
}

const key = licenseKey();
if (!await app.check(key)) {
  console.log(app.message);
  process.exit(1);
}
console.log("Status: active");
console.log(app.expiresAt ? `Expires: ${app.expiresAt}` : "Expires: Lifetime");
