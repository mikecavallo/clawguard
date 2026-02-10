/**
 * ClawGuard Docs — Shared Scripts
 * Adds click-to-copy buttons on all <pre> code blocks.
 */
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('pre').forEach(pre => {
    const btn = document.createElement('button');
    btn.className = 'copy-btn';
    btn.setAttribute('aria-label', 'Copy to clipboard');
    btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M4 4V1.5A1.5 1.5 0 0 1 5.5 0h9A1.5 1.5 0 0 1 16 1.5v9a1.5 1.5 0 0 1-1.5 1.5H12" stroke="currentColor" stroke-width="1.5"/><rect x="0" y="4" width="12" height="12" rx="1.5" stroke="currentColor" stroke-width="1.5"/></svg>';

    btn.addEventListener('click', () => {
      const code = pre.querySelector('code');
      if (!code) return;

      // Extract clean text: strip prompt symbols and output-only lines
      const raw = code.innerText;
      const lines = raw.split('\n');
      const cleaned = lines
        .map(line => line.replace(/^\$\s*/, ''))  // strip leading "$ "
        .filter(line => line.trim().length > 0)
        .join('\n');

      navigator.clipboard.writeText(cleaned).then(() => {
        btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M2 8.5l3.5 3.5L14 3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M4 4V1.5A1.5 1.5 0 0 1 5.5 0h9A1.5 1.5 0 0 1 16 1.5v9a1.5 1.5 0 0 1-1.5 1.5H12" stroke="currentColor" stroke-width="1.5"/><rect x="0" y="4" width="12" height="12" rx="1.5" stroke="currentColor" stroke-width="1.5"/></svg>';
          btn.classList.remove('copied');
        }, 2000);
      });
    });

    pre.appendChild(btn);
  });
});
