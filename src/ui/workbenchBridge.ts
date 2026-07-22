/**
 * Decoupled hand-off to the Verify Workbench, avoiding event-ordering races and
 * circular imports between main.ts, the workbench, and the vectors panel.
 * Only PUBLIC verification artifacts ever travel through here.
 */
export interface LoadVerifyDetail {
  pubkeyHex: string;
  sigHex: string;
  msgHex: string;
}

let loader: ((d: LoadVerifyDetail) => void) | null = null;
let opener: ((d?: LoadVerifyDetail) => void) | null = null;

/** The workbench registers how to populate itself. */
export function setVerifyLoader(fn: (d: LoadVerifyDetail) => void): void {
  loader = fn;
}
export function loadVerifyCase(d: LoadVerifyDetail): void {
  loader?.(d);
}

/** main.ts registers how to render + switch to the workbench tab. */
export function setVerifyOpener(fn: (d?: LoadVerifyDetail) => void): void {
  opener = fn;
}
/** Any panel can request the workbench, optionally pre-loaded with a case. */
export function openVerifyWorkbench(d?: LoadVerifyDetail): void {
  opener?.(d);
}
