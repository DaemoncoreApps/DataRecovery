export const bytes = (n: number) =>
  n < 1024
    ? `${n} B`
    : `${(n / 1024 ** Math.floor(Math.log(n) / Math.log(1024))).toFixed(2)} ${["B", "KiB", "MiB", "GiB", "TiB", "PiB"][Math.floor(Math.log(n) / Math.log(1024))]}`;

export function parseByteOffset(input: string, field = "byte offset"): number {
  const value = input.trim();
  if (!/^\d+$/.test(value) && !/^0x[\da-f]+$/i.test(value)) {
    throw new Error(`Enter ${field} as a nonnegative decimal or 0x hexadecimal value.`);
  }
  const offset = Number(value);
  if (!Number.isSafeInteger(offset) || offset < 0) {
    throw new Error(`${field} exceeds the supported safe integer range.`);
  }
  return offset;
}
