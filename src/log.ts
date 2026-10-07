// One line per event: `<time> <event> key=value …`. Only methods, paths, statuses, sizes, times and
// rc.8's lifecycle are ever logged: never a request or response body, never a header.

type Value = string | number | boolean | null | undefined;

export function log(event: string, fields: Record<string, Value> = {}): void {
  const parts = [new Date().toISOString(), event];
  for (const [k, v] of Object.entries(fields)) {
    if (v === undefined) continue;
    parts.push(`${k}=${typeof v === 'string' && /\s/.test(v) ? JSON.stringify(v) : String(v)}`);
  }
  process.stdout.write(`${parts.join(' ')}\n`);
}
