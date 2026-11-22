/** Tiny, dependency-free DOM helpers shared by the panels. */

type Attrs = Record<string, string | number | boolean | EventListener | undefined>;
type Child = Node | string | null | undefined;

/** Hyperscript: h('button', { class: 'x', onclick: fn }, 'label'). */
export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;
    if (key.startsWith('on') && typeof value === 'function') {
      node.addEventListener(key.slice(2).toLowerCase(), value as EventListener);
    } else if (key === 'class') {
      node.className = String(value);
    } else if (value === true) {
      node.setAttribute(key, '');
    } else {
      node.setAttribute(key, String(value));
    }
  }
  for (const c of children) {
    if (c == null) continue;
    node.append(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return node;
}

export function clear(node: HTMLElement): void {
  node.replaceChildren();
}

/** A labelled read-only value shown as wrapping monospace (no scroll region needed). */
export function field(label: string, value: string, opts: { mono?: boolean; sub?: string } = {}): HTMLElement {
  return h(
    'div',
    { class: 'field' },
    h('span', { class: 'field-label' }, label, opts.sub ? h('span', { class: 'field-sub' }, ` ${opts.sub}`) : null),
    h('code', { class: opts.mono === false ? 'field-value plain' : 'field-value' }, value),
  );
}

/** A big pass/fail verdict: icon + text + color (never color alone). */
export function verdict(state: 'pass' | 'fail' | 'alarm', text: string): HTMLElement {
  const icon = state === 'pass' ? '✓' : state === 'alarm' ? '⚠' : '✕';
  return h(
    'div',
    { class: `verdict verdict-${state}`, role: 'status' },
    h('span', { class: 'verdict-icon', 'aria-hidden': 'true' }, icon),
    h('span', {}, text),
  );
}

/** Section heading + intro paragraph(s) for a panel. */
export function panelIntro(title: string, ...paras: (string | HTMLElement)[]): HTMLElement {
  return h(
    'div',
    { class: 'panel-intro' },
    h('h2', {}, title),
    ...paras.map((p) => (typeof p === 'string' ? h('p', {}, p) : p)),
  );
}

/** A "not production" / scoping note. */
export function note(kind: 'info' | 'danger' | 'caveat', ...children: Child[]): HTMLElement {
  return h('p', { class: `callout callout-${kind}` }, ...children);
}

/** Replace evidence that no longer belongs to the controls currently on screen. */
export function evidenceRetired(text: string): HTMLElement {
  return h(
    'p',
    { class: 'callout callout-caveat evidence-retired', role: 'status', 'aria-live': 'polite' },
    text,
  );
}

/** Middle-truncate a long hex string for compact display; full value stays in title. */
export function short(hex: string, keep = 10): string {
  if (hex.length <= keep * 2 + 1) return hex;
  return `${hex.slice(0, keep)}…${hex.slice(-keep)}`;
}

/**
 * A copy-to-clipboard button. `secret: true` marks it as copying key material
 * (styled distinctly, named distinctly) so public and private values are never
 * treated as interchangeable.
 *
 * `describes` says WHAT is copied and is appended to the visible text; it is not
 * the whole accessible name. That is the point of the parameter, and it replaced
 * a `label` that set the name outright.
 *
 * WHY. The visible text is `base`, and WCAG 2.5.3 Label in Name requires the
 * accessible name to contain it — axe's `label-content-name-mismatch`, which
 * became a failure here when @axe-core/playwright moved 4.13 -> 4.14. The secret
 * button was named "Copy private key (secret)" over the visible text "Copy
 * secret": the words are all present but not as a contiguous string, so the name
 * did not contain the label and the rule fired. A caller supplying a full name
 * can always get that wrong again, and nothing in the signature stopped it. With
 * `describes`, the visible text is always a PREFIX of the accessible name and the
 * mismatch is unreachable rather than merely fixed.
 */
export function copyLabels(opts: { describes?: string; secret?: boolean } = {}): { visible: string; name: string } {
  const visible = opts.secret ? 'Copy secret' : 'Copy';
  return { visible, name: opts.describes ? `${visible} ${opts.describes}` : visible };
}

export function copyButton(getText: () => string, opts: { describes?: string; secret?: boolean } = {}): HTMLButtonElement {
  const { visible: base, name } = copyLabels(opts);
  const btn = h(
    'button',
    {
      type: 'button',
      class: `btn btn-ghost copy-btn${opts.secret ? ' copy-secret' : ''}`,
      'aria-label': name,
    },
    base,
  ) as HTMLButtonElement;
  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(getText());
      btn.textContent = 'Copied';
    } catch {
      btn.textContent = 'Copy failed';
    }
    setTimeout(() => (btn.textContent = base), 1200);
  });
  return btn;
}

/**
 * A lightweight "predict before you reveal" check: one misconception, a couple of
 * choices, and an immediate explanation. No score, account, or gamification; the
 * lab stays fully usable whether or not it is answered.
 */
export function learnerCheck(
  question: string,
  options: { label: string; correct: boolean }[],
  explanation: string,
): HTMLElement {
  const feedback = h('div', { class: 'check-feedback', role: 'status', 'aria-live': 'polite' });
  const buttons = options.map((o) =>
    h('button', {
      type: 'button',
      class: 'btn btn-ghost check-opt',
      onclick: () => {
        clear(feedback);
        feedback.append(
          h('span', { class: `pill pill-${o.correct ? 'ok' : 'bad'}` },
            h('span', { 'aria-hidden': 'true' }, o.correct ? '✓ ' : '✕ '),
            o.correct ? 'Correct' : 'Not quite',
          ),
          h('p', { class: 'check-explain' }, explanation),
        );
      },
    }, o.label),
  );
  return h(
    'details',
    { class: 'learner-check' },
    h('summary', {}, 'Quick check'),
    h('div', { class: 'check-body' },
      h('p', { class: 'check-q' }, question),
      h('div', { class: 'input-row', role: 'group', 'aria-label': question }, ...buttons),
      feedback,
    ),
  );
}
