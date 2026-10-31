export const bytes = (n: number) =>
  n < 1024
    ? `${n} B`
    : `${(n / 1024 ** Math.floor(Math.log(n) / Math.log(1024))).toFixed(2)} ${["B", "KiB", "MiB", "GiB", "TiB", "PiB"][Math.floor(Math.log(n) / Math.log(1024))]}`;
