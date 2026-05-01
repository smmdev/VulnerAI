(function () {
  'use strict';

  var prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function scan() {
    var elements = document.querySelectorAll('.reveal:not(.is-visible)');
    if (prefersReducedMotion) {
      elements.forEach(function (el) { el.classList.add('is-visible'); });
      return;
    }
    elements.forEach(function (el) { observer.observe(el); });
  }

  var observer = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (!entry.isIntersecting) return;
      entry.target.classList.add('is-visible');
      observer.unobserve(entry.target);
    });
  }, {
    threshold: 0.08,
    rootMargin: '0px 0px -36px 0px'
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scan);
  } else {
    scan();
  }

  /* Called by dynamic renderers (catalog, index.js) after injecting new nodes */
  window.__vulneraiRevealScan = scan;
})();
