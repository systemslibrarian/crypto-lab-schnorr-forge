import './style.css';
import { renderSignPanel } from './ui/signPanel.js';
import { renderEquationPanel } from './ui/equationPanel.js';
import { renderAttackPanel } from './ui/attackPanel.js';
import { renderVectorsPanel } from './ui/vectorsPanel.js';
import { renderLinearityPanel } from './ui/linearityPanel.js';

type PanelKey = 'sign' | 'equation' | 'attack' | 'vectors' | 'linearity';

const renderers: Record<PanelKey, (root: HTMLElement) => void> = {
  sign: renderSignPanel,
  equation: renderEquationPanel,
  attack: renderAttackPanel,
  vectors: renderVectorsPanel,
  linearity: renderLinearityPanel,
};

const rendered = new Set<PanelKey>();

function panelEl(key: PanelKey): HTMLElement {
  return document.getElementById(`panel-${key}`) as HTMLElement;
}

function ensureRendered(key: PanelKey): void {
  if (rendered.has(key)) return;
  renderers[key](panelEl(key));
  rendered.add(key);
}

function selectTab(key: PanelKey): void {
  const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('.tab-btn'));
  for (const tab of tabs) {
    const isActive = tab.dataset.panel === key;
    tab.setAttribute('aria-selected', String(isActive));
    tab.tabIndex = isActive ? 0 : -1;
    tab.classList.toggle('active', isActive);
    const panel = panelEl(tab.dataset.panel as PanelKey);
    panel.hidden = !isActive;
  }
  ensureRendered(key);
}

function wireTabs(): void {
  const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('.tab-btn'));
  tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => selectTab(tab.dataset.panel as PanelKey));
    // Roving-tabindex arrow-key navigation across the tablist (WAI-ARIA pattern).
    tab.addEventListener('keydown', (e) => {
      let next = -1;
      if (e.key === 'ArrowRight') next = (i + 1) % tabs.length;
      else if (e.key === 'ArrowLeft') next = (i - 1 + tabs.length) % tabs.length;
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = tabs.length - 1;
      if (next >= 0) {
        e.preventDefault();
        tabs[next].focus();
        selectTab(tabs[next].dataset.panel as PanelKey);
      }
    });
  });
}

wireTabs();
selectTab('sign');
