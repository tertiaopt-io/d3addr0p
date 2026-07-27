// AIM-style special characters for profiles and away messages. The stored text keeps the tokens LITERAL;
// they are substituted at display time (a peer viewing your profile) or send time (an away auto-reply):
//   %n = the other party's name   %d = the current date   %t = the current time
// Shared by the worker (away replies, controller.ts) and the main thread (profile display, app.ts).

/** Substitute %n / %d / %t. `name` fills %n (a peer or viewer name) and is backslash-escaped so it cannot
 * smuggle formatting markers into the rendered output; `at` is the wall-clock ms for %d/%t (default now). */
export function substituteSpecials(text: string, opts: { name?: string; at?: number }): string {
  if (!/%[ndt]/.test(text)) {
    return text; // nothing to do; keep the exact string
  }
  const d = opts.at !== undefined ? new Date(opts.at) : new Date();
  const pad = (n: number): string => String(n).padStart(2, '0');
  const date = `${d.getMonth() + 1}/${d.getDate()}/${d.getFullYear()}`;
  const h = d.getHours();
  const time = `${h % 12 || 12}:${pad(d.getMinutes())} ${h < 12 ? 'AM' : 'PM'}`;
  const name = (opts.name ?? '').replace(/[\\*_[%]/g, (c) => `\\${c}`);
  return text.replace(/%[ndt]/g, (m) => (m === '%n' ? name : m === '%d' ? date : time));
}
