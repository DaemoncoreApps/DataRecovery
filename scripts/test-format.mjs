import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import ts from "typescript";

const source = await readFile(
  new URL("../src/format.ts", import.meta.url),
  "utf8",
);
const { outputText } = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.ESNext,
    target: ts.ScriptTarget.ES2022,
  },
});
const moduleUrl = `data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`;
const { parseByteOffset } = await import(moduleUrl);

for (const [input, expected] of [
  ["0", 0],
  ["42", 42],
  [" 42 ", 42],
  ["0x2a", 42],
  ["0XfF", 255],
]) {
  assert.equal(
    parseByteOffset(input),
    expected,
    `accepted offset ${JSON.stringify(input)}`,
  );
}

for (const input of [
  "",
  "   ",
  "0x",
  "0xzz",
  "-1",
  "1.5",
  "1e3",
  "9007199254740992",
]) {
  assert.throws(
    () => parseByteOffset(input),
    Error,
    `rejected offset ${JSON.stringify(input)}`,
  );
}

console.log("Strict byte-offset checks passed (5 accepted, 8 rejected).");
