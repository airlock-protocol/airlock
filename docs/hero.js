/* Airlock hero — the airlock in motion.
 * Agents approach a verification gate; most are cleared (gold), the
 * unauthorized are denied (red) at the gate. Purposeful, not decorative:
 * it IS the product. Content-first (low opacity, right-side negative space),
 * theme-aware, pauses off-screen/hidden, and respects reduced-motion.
 */
(function () {
  'use strict';

  var canvas = document.getElementById('hero-canvas');
  if (!canvas || !canvas.getContext) return;
  var ctx = canvas.getContext('2d');

  var reduce =
    window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  var W = 0, H = 0, dpr = 1, gateX = 0, gateTop = 0, gateBot = 0;
  var particles = [], scan = 0, last = 0, running = false, onscreen = true;

  function colors() {
    var light = document.documentElement.getAttribute('data-theme') === 'light';
    return light
      ? { ink: '20,24,33', gold: '154,123,31', red: '176,46,46' }
      : { ink: '232,232,237', gold: '184,149,48', red: '248,81,73' };
  }

  function reset(p, fromLeft) {
    p.x = fromLeft ? -20 - Math.random() * W * 0.4 : Math.random() * gateX;
    p.y = gateTop + Math.random() * (gateBot - gateTop);
    p.speed = 18 + Math.random() * 34; // px/sec — slow, premium
    p.len = 6 + Math.random() * 10;
    p.denied = Math.random() < 0.16;
    p.state = 'approach';
    p.life = 1;
    p.ring = 0;
    return p;
  }

  function build() {
    gateX = W * 0.64;
    gateTop = H * 0.14;
    gateBot = H * 0.86;
    var n = Math.max(12, Math.min(44, Math.round(W / 28)));
    particles = [];
    for (var i = 0; i < n; i++) particles.push(reset({}, false));
  }

  function resize() {
    var r = canvas.getBoundingClientRect();
    W = r.width; H = r.height;
    if (!W || !H) return;
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    build();
  }

  function update(dt) {
    for (var i = 0; i < particles.length; i++) {
      var p = particles[i];
      if (p.state === 'approach') {
        p.x += p.speed * dt;
        if (p.x >= gateX) {
          if (p.denied) { p.state = 'denied'; p.x = gateX; p.ring = 0; }
          else { p.state = 'cleared'; }
        }
      } else if (p.state === 'cleared') {
        p.x += p.speed * dt;
        if (p.x - p.len > W) reset(p, true);
      } else { // denied
        p.ring += dt * 34;
        p.life -= dt * 1.1;
        if (p.life <= 0) reset(p, true);
      }
    }
    scan += dt * 0.25;
    if (scan > 1) scan -= 1;
  }

  function draw() {
    var c = colors();
    ctx.clearRect(0, 0, W, H);

    // the gate
    ctx.strokeStyle = 'rgba(' + c.gold + ',0.14)';
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(gateX, gateTop); ctx.lineTo(gateX, gateBot); ctx.stroke();

    // scanning pulse travelling down the gate
    var sy = gateTop + (gateBot - gateTop) * scan;
    var g = ctx.createLinearGradient(0, sy - 26, 0, sy + 26);
    g.addColorStop(0, 'rgba(' + c.gold + ',0)');
    g.addColorStop(0.5, 'rgba(' + c.gold + ',0.5)');
    g.addColorStop(1, 'rgba(' + c.gold + ',0)');
    ctx.strokeStyle = g; ctx.lineWidth = 2;
    ctx.beginPath(); ctx.moveTo(gateX, sy - 26); ctx.lineTo(gateX, sy + 26); ctx.stroke();

    // agents
    ctx.lineCap = 'round';
    for (var i = 0; i < particles.length; i++) {
      var p = particles[i];
      if (p.state === 'denied') {
        ctx.fillStyle = 'rgba(' + c.red + ',' + 0.7 * p.life + ')';
        ctx.beginPath(); ctx.arc(gateX, p.y, 2.2, 0, 6.2832); ctx.fill();
        ctx.strokeStyle = 'rgba(' + c.red + ',' + 0.5 * p.life + ')';
        ctx.lineWidth = 1;
        ctx.beginPath(); ctx.arc(gateX, p.y, p.ring, 0, 6.2832); ctx.stroke();
      } else {
        var near = Math.min(1, Math.max(0, p.x / gateX));
        var cleared = p.state === 'cleared';
        var col = cleared ? c.gold : c.ink;
        var a = cleared ? 0.75 : 0.14 + near * 0.45;
        ctx.strokeStyle = 'rgba(' + col + ',' + a + ')';
        ctx.lineWidth = 1.4;
        ctx.beginPath(); ctx.moveTo(p.x - p.len, p.y); ctx.lineTo(p.x, p.y); ctx.stroke();
        ctx.fillStyle = 'rgba(' + col + ',' + Math.min(0.9, a + 0.15) + ')';
        ctx.beginPath(); ctx.arc(p.x, p.y, 1.3, 0, 6.2832); ctx.fill();
      }
    }
  }

  function frame(t) {
    if (!running) return;
    var dt = last ? Math.min(0.05, (t - last) / 1000) : 0.016;
    last = t;
    update(dt);
    draw();
    requestAnimationFrame(frame);
  }

  function start() {
    if (!running && onscreen && !document.hidden && W) {
      running = true; last = 0; requestAnimationFrame(frame);
    }
  }
  function stop() { running = false; }

  function init() {
    resize();
    if (!W) return;
    if (reduce) { update(0); draw(); return; } // one calm static frame
    start();
  }

  var rz;
  window.addEventListener('resize', function () {
    clearTimeout(rz);
    rz = setTimeout(function () { resize(); if (reduce) draw(); }, 150);
  });

  if ('IntersectionObserver' in window) {
    new IntersectionObserver(function (es) {
      onscreen = es[0].isIntersecting;
      if (reduce) return;
      if (onscreen) start(); else stop();
    }, { threshold: 0.01 }).observe(canvas);
  }
  document.addEventListener('visibilitychange', function () {
    if (reduce) return;
    if (document.hidden) stop(); else start();
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
