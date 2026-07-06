/* Airlock — scroll reveal. Sections rise + fade as they enter view (Apple-style).
 * Progressive enhancement: if JS or IntersectionObserver is unavailable, or
 * reduced-motion is set, we never add the `reveal-ready` gate, so all content
 * stays fully visible. Elements already in view at load show instantly (no
 * flash); only below-the-fold sections animate in.
 */
(function () {
  'use strict';

  var reduce =
    window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduce || !('IntersectionObserver' in window)) return;

  var SEL =
    '.demo-header,.demo-terminals,.objection-inner,.incidents-header,' +
    '.stat-band,.incidents-grid,.arch-header,.arch-flow,.cedar-block,' +
    '.proof-grid,.badge-inner,.protocol .container,.cta .container';

  function run() {
    document.documentElement.classList.add('reveal-ready');
    var vh = window.innerHeight || document.documentElement.clientHeight;

    var io = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (e) {
          if (e.isIntersecting) {
            e.target.classList.add('in');
            io.unobserve(e.target);
          }
        });
      },
      { threshold: 0.12, rootMargin: '0px 0px -8% 0px' }
    );

    var nodes = document.querySelectorAll(SEL);
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      if (el.getBoundingClientRect().top < vh * 0.92) {
        // Already in view: show immediately, no animation, no flash.
        el.classList.add('reveal', 'in');
      } else {
        el.classList.add('reveal');
        io.observe(el);
      }
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run);
  } else {
    run();
  }
})();
