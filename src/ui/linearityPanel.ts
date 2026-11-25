import { h, clear, field, verdict, panelIntro, note, learnerCheck, evidenceRetired } from './dom.js';
import { aggregateTwo } from '../schnorr/aggregate.js';
import { bytesToBig, randomBytes, N, utf8 } from '../schnorr/field.js';

const rndScalar = (): bigint => (bytesToBig(randomBytes(32)) % (N - 1n)) + 1n;

/**
 * Why linearity matters: two independent signers produce responses s1, s2 that
 * literally ADD into one combined response that the ordinary verifier accepts
 * against the summed public key. This is the seed of Schnorr multisig.
 */
export function renderLinearityPanel(root: HTMLElement): void {
  clear(root);

  let x1 = rndScalar(), x2 = rndScalar(), k1 = rndScalar(), k2 = rndScalar();
  const msgInput = h('textarea', { id: 'lin-msg', class: 'msg-input', rows: 1, spellcheck: false }, 'We jointly authorize this.') as HTMLTextAreaElement;
  const output = h('div', { class: 'output', id: 'linearity-output' });
  let hasEvidence = false;

  function retireEvidence(): void {
    if (!hasEvidence) return;
    hasEvidence = false;
    clear(output);
    output.append(evidenceRetired('The shared message changed — combine fresh responses before trusting the aggregate verdict.'));
  }

  function run(): void {
    clear(output);
    const r = aggregateTwo(utf8(msgInput.value), x1, x2, k1, k2);
    const [A, B] = r.signers;

    output.append(
      h('div', { class: 'sig-pair' },
        h('div', { class: 'sig-card' },
          h('h3', {}, 'Signer A'),
          field('public key  P₁.x', A.Px),
          field('response  s₁ = k₁ + e·x₁', `0x${A.s.toString(16)}`),
        ),
        h('div', { class: 'sig-card' },
          h('h3', {}, 'Signer B'),
          field('public key  P₂.x', B.Px),
          field('response  s₂ = k₂ + e·x₂', `0x${B.s.toString(16)}`),
        ),
      ),
      h('div', { class: 'agg-block' },
        h('p', { class: 'eq-derivation' }, 's = s₁ + s₂ = (k₁+k₂) + e·(x₁+x₂)   ⇒   s·G = (R₁+R₂) + e·(P₁+P₂)'),
        field('shared challenge  e (over R₁+R₂ and P₁+P₂)', `0x${r.e.toString(16)}`),
        field('combined key  (P₁+P₂).x', r.aggPubX),
        field('combined commitment  (R₁+R₂).x', r.aggRx),
        field('combined response  s = s₁ + s₂', `${r.sIndividualSum}  =  0x${r.s.toString(16)}`),
        r.verifies
          ? verdict('pass', 'The ordinary verifier accepts one combined (R, s) signature for the summed key')
          : verdict('fail', 'aggregate did not verify (unexpected)'),
      ),
    );
    hasEvidence = true;
  }

  root.append(
    panelIntro(
      'Why Linearity Matters',
      'Look again at the response: s = k + e·x is linear in the secret x and the nonce k. Add two signers’ responses and the parts line up perfectly — the nonces add, the keys add, the challenge is shared. The sum is a single valid signature for the combined public key.',
      'That one property is the foundation of Schnorr multisig, key aggregation, and threshold signing. ECDSA’s response is not linear, which is why none of this is easy there.',
    ),
    h('div', { class: 'controls' },
      h('div', { class: 'control' },
        h('label', { for: 'lin-msg' }, 'Shared message'),
        msgInput,
      ),
      h('div', { class: 'input-row' },
        h('button', { type: 'button', class: 'btn btn-primary', onclick: run }, 'Sign separately, then combine'),
        h('button', { type: 'button', class: 'btn btn-ghost', onclick: () => {
          x1 = rndScalar(); x2 = rndScalar(); k1 = rndScalar(); k2 = rndScalar();
          run();
        } }, 'New signers'),
      ),
    ),
    output,
    note('caveat',
      h('strong', {}, 'Illustrative simplification. '),
      'This teaser uses textbook Schnorr over full points and adds nonces naively — which is insecure against rogue-key and Wagner-style attacks. Making key aggregation safe is exactly what ',
      h('a', { href: 'https://systemslibrarian.github.io/crypto-lab-musig-gate/', target: '_blank', rel: 'noopener noreferrer' }, 'MuSig2'),
      ' does (key-aggregation coefficients, two nonces per signer, two rounds); ',
      h('a', { href: 'https://systemslibrarian.github.io/crypto-lab-frost-threshold/', target: '_blank', rel: 'noopener noreferrer' }, 'FROST'),
      ' solves a different problem — threshold signing from one Shamir-shared key, with a binding factor over the message and the commitment list. The linearity shown here is real; the security engineering is what those protocols contribute.',
    ),
    learnerCheck(
      'Since two honest signers combine cleanly here, is this naive add-the-keys aggregation safe to deploy?',
      [
        { label: 'Yes, it just works', correct: false },
        { label: 'No — a malicious signer can break it', correct: true },
      ],
      'A participant who chooses their key or nonce after seeing the others (a rogue-key or Wagner attack) can forge for the group. They are two different constructions. MuSig2 (BIP-327) aggregates independent keys, weighting each by a key-aggregation coefficient hashed from the key list, and has every signer send two nonces instead of one — which is what lets it drop MuSig1’s separate nonce-commitment round. FROST (RFC 9591) aggregates nothing: one group key is Shamir-shared among the signers, and each signer commits to two nonces that a per-signer binding factor ties to the message and to the exact commitment list.',
    ),
  );

  msgInput.addEventListener('input', retireEvidence);

  run();
}
