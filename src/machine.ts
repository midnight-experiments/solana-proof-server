// What the package can tell about the machine it runs on: the container's limits when it has any
// (cgroup v2, then v1), else the host's (I-62b `machine`).

import { readFileSync } from 'node:fs';
import { availableParallelism, totalmem } from 'node:os';

function read(path: string): string | undefined {
  try {
    return readFileSync(path, 'utf8').trim();
  } catch {
    return undefined;
  }
}

export function machine(): { cpus: number; memoryBytes: number | null } {
  let cpus = availableParallelism();
  const cpuMax = read('/sys/fs/cgroup/cpu.max'); // "max 100000" or "<quota> <period>"
  if (cpuMax) {
    const [quota, period] = cpuMax.split(/\s+/);
    if (quota && quota !== 'max' && period && Number(period) > 0) {
      cpus = Math.max(1, Math.min(cpus, Math.ceil(Number(quota) / Number(period))));
    }
  }
  let memoryBytes: number | null = null;
  const v2 = read('/sys/fs/cgroup/memory.max');
  if (v2 && v2 !== 'max' && /^\d+$/.test(v2)) memoryBytes = Number(v2);
  if (memoryBytes === null) {
    const v1 = read('/sys/fs/cgroup/memory/memory.limit_in_bytes');
    // cgroup v1 reports "no limit" as a huge number (2^63 rounded to the page size).
    if (v1 && /^\d+$/.test(v1) && Number(v1) < 2 ** 60) memoryBytes = Number(v1);
  }
  const total = totalmem();
  const host = Number.isFinite(total) && total > 0 ? total : null;
  if (memoryBytes === null) memoryBytes = host;
  else if (host !== null) memoryBytes = Math.min(memoryBytes, host);
  return { cpus, memoryBytes };
}
