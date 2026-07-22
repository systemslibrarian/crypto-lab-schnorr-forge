import { h } from './dom.js';
import { hexToBytes, bytesToHex, utf8 } from '../schnorr/field.js';

export type MsgMode = 'utf8' | 'hex';

export interface MsgReadOk {
  ok: true;
  bytes: Uint8Array;
  byteLen: number;
}
export interface MsgReadErr {
  ok: false;
  error: string;
}
export type MsgRead = MsgReadOk | MsgReadErr;

export interface MessageInput {
  element: HTMLElement;
  read(): MsgRead;
  onChange(cb: () => void): void;
  setValue(mode: MsgMode, text: string): void;
}

/**
 * BIP-340 signs byte arrays, not text. This control lets the user supply the
 * exact bytes as UTF-8 text OR as hex, shows the resulting byte length, and
 * fails before any crypto runs on malformed hex. Leading zero bytes survive in
 * hex mode ("00…"), which UTF-8 text cannot express.
 */
export function createMessageInput(opts: {
  id: string;
  label: string;
  initialText?: string;
  initialMode?: MsgMode;
}): MessageInput {
  let mode: MsgMode = opts.initialMode ?? 'utf8';
  const listeners: Array<() => void> = [];

  const textarea = h('textarea', {
    id: opts.id,
    class: 'msg-input',
    rows: 2,
    spellcheck: false,
    autocomplete: 'off',
  }, opts.initialText ?? '') as HTMLTextAreaElement;

  const status = h('p', { class: 'help msg-status', role: 'status', 'aria-live': 'polite' });

  const utf8Btn = h('button', { type: 'button', class: 'seg-btn', 'aria-pressed': 'true' }, 'UTF-8 text') as HTMLButtonElement;
  const hexBtn = h('button', { type: 'button', class: 'seg-btn', 'aria-pressed': 'false' }, 'Hex bytes') as HTMLButtonElement;

  function read(): MsgRead {
    const raw = textarea.value;
    if (mode === 'utf8') {
      const bytes = utf8(raw);
      return { ok: true, bytes, byteLen: bytes.length };
    }
    try {
      const bytes = hexToBytes(raw);
      return { ok: true, bytes, byteLen: bytes.length };
    } catch (e) {
      return { ok: false, error: (e as Error).message };
    }
  }

  function refresh(): void {
    const r = read();
    if (r.ok) {
      status.textContent = `${r.byteLen} byte${r.byteLen === 1 ? '' : 's'}`;
      textarea.setAttribute('aria-invalid', 'false');
    } else {
      status.textContent = `invalid hex — ${r.error}`;
      textarea.setAttribute('aria-invalid', 'true');
    }
    for (const cb of listeners) cb();
  }

  function paintButtons(): void {
    utf8Btn.setAttribute('aria-pressed', String(mode === 'utf8'));
    hexBtn.setAttribute('aria-pressed', String(mode === 'hex'));
    utf8Btn.classList.toggle('active', mode === 'utf8');
    hexBtn.classList.toggle('active', mode === 'hex');
  }

  function setMode(next: MsgMode): void {
    if (next === mode) return;
    const cur = read();
    // Convert the current bytes into the new representation when possible.
    if (cur.ok) {
      textarea.value = next === 'hex' ? bytesToHex(cur.bytes) : new TextDecoder().decode(cur.bytes);
    }
    mode = next;
    paintButtons();
    refresh();
  }

  utf8Btn.classList.add('active');
  textarea.addEventListener('input', refresh);
  utf8Btn.addEventListener('click', () => setMode('utf8'));
  hexBtn.addEventListener('click', () => setMode('hex'));

  const element = h(
    'div',
    { class: 'control msg-control' },
    h('label', { for: opts.id }, opts.label),
    h('div', { class: 'seg', role: 'group', 'aria-label': `${opts.label} encoding` }, utf8Btn, hexBtn),
    textarea,
    status,
  );

  // Prime the byte-count display.
  queueMicrotask(refresh);

  return {
    element,
    read,
    onChange: (cb) => listeners.push(cb),
    setValue: (m, text) => {
      // Set explicit text for mode `m` verbatim — no re-encoding conversion.
      mode = m;
      textarea.value = text;
      paintButtons();
      refresh();
    },
  };
}
