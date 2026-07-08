/* Airlock — light/dark theme toggle, shared across all pages.
 * The initial theme is set by a tiny inline script in <head> (no flash);
 * this file wires the toggle button and keeps meta/aria in sync.
 */
(function () {
  'use strict';

  var KEY = 'airlock-theme';
  var root = document.documentElement;

  function apply(theme) {
    root.setAttribute('data-theme', theme);
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', theme === 'light' ? '#F6F8FB' : '#12151C');
    var btn = document.getElementById('theme-toggle');
    if (btn) {
      btn.setAttribute('aria-pressed', theme === 'light' ? 'true' : 'false');
      btn.setAttribute('title', theme === 'light' ? 'Switch to dark' : 'Switch to light');
    }
  }

  // Sync meta/aria with whatever the inline head script already applied.
  apply(root.getAttribute('data-theme') === 'light' ? 'light' : 'dark');

  var toggle = document.getElementById('theme-toggle');
  if (toggle) {
    toggle.addEventListener('click', function () {
      var next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      apply(next);
      try { localStorage.setItem(KEY, next); } catch (e) {}
    });
  }

  // ── Wordmark: AIRLOCK collapses to "A/" once you scroll ──
  if (document.querySelector('.nav-logo .wm-rest')) {
    var onScroll = function () {
      root.classList.toggle('wm-scrolled', window.scrollY > 40);
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
  }
})();
