/* agent-sentinel site script: theme toggle, mobile menu, tabs, copy buttons,
   current-section highlight, reading progress, back to top, code-block fades.
   No dependencies and no network requests. The page works without it.
   The page's CSP enforces Trusted Types, so this script must never use
   innerHTML, outerHTML, insertAdjacentHTML or document.write; it builds
   nodes with createElement and textContent. */
(function () {
  'use strict';

  var root = document.documentElement;
  var THEME_KEY = 'agent-sentinel-theme';
  var THEME_COLORS = { dark: '#0a0a0a', light: '#d0d0d0' };

  // Runs in <head>, before first paint, so the stored theme applies at once.
  root.classList.add('js');

  function readStoredTheme() {
    try {
      var value = window.localStorage.getItem(THEME_KEY);
      return value === 'light' || value === 'dark' ? value : null;
    } catch (err) {
      return null;
    }
  }

  function storeTheme(value) {
    try {
      window.localStorage.setItem(THEME_KEY, value);
    } catch (err) {
      /* Storage can be blocked. The choice then lasts for this page only. */
    }
  }

  function systemTheme() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }

  function currentTheme() {
    var chosen = root.getAttribute('data-theme');
    return chosen === 'light' || chosen === 'dark' ? chosen : systemTheme();
  }

  // A chosen theme overrides the system one, so both theme-color metas must
  // carry its color. They sit above this script in <head>, so they exist now.
  function syncThemeColor(theme) {
    var metas = document.querySelectorAll('meta[name="theme-color"]');
    for (var i = 0; i < metas.length; i += 1) {
      metas[i].setAttribute('content', THEME_COLORS[theme]);
    }
  }

  var stored = readStoredTheme();
  if (stored) {
    root.setAttribute('data-theme', stored);
    syncThemeColor(stored);
  }

  function initTheme() {
    var button = document.querySelector('[data-theme-toggle]');
    if (!button) {
      return;
    }

    function describe() {
      var next = currentTheme() === 'dark' ? 'light' : 'dark';
      button.setAttribute('aria-label', 'Switch to ' + next + ' theme');
      button.setAttribute('title', 'Switch to ' + next + ' theme');
    }

    button.addEventListener('click', function () {
      var next = currentTheme() === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      storeTheme(next);
      syncThemeColor(next);
      describe();
    });

    if (window.matchMedia) {
      var query = window.matchMedia('(prefers-color-scheme: light)');
      if (query.addEventListener) {
        query.addEventListener('change', describe);
      }
    }

    describe();
  }

  function initMenu() {
    var button = document.querySelector('[data-menu-toggle]');
    var nav = document.getElementById('site-nav');
    if (!button || !nav) {
      return;
    }

    function isOpen() {
      return button.getAttribute('aria-expanded') === 'true';
    }

    // The button keeps its name, "Menu"; aria-expanded carries the state.
    function setOpen(open) {
      nav.classList.toggle('is-open', open);
      button.setAttribute('aria-expanded', open ? 'true' : 'false');
    }

    button.addEventListener('click', function () {
      var open = !isOpen();
      setOpen(open);
      if (open) {
        var first = nav.querySelector('a');
        if (first) {
          first.focus();
        }
      }
    });

    nav.addEventListener('click', function (event) {
      if (event.target && event.target.closest && event.target.closest('a')) {
        setOpen(false);
      }
    });

    // A click or tap anywhere outside the open panel closes it.
    document.addEventListener('click', function (event) {
      if (isOpen() && !nav.contains(event.target) && !button.contains(event.target)) {
        setOpen(false);
      }
    });

    // Focus that moves out of the header closes the panel, so the panel
    // never covers the element that has focus.
    var header = button.closest('.site-header');
    document.addEventListener('focusin', function (event) {
      if (isOpen() && header && !header.contains(event.target)) {
        setOpen(false);
      }
    });

    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && isOpen()) {
        setOpen(false);
        button.focus();
      }
    });

    // The panel only exists on narrow screens. Reset it when the window grows.
    if (window.matchMedia) {
      var wide = window.matchMedia('(min-width: 73em)');
      if (wide.addEventListener) {
        wide.addEventListener('change', function (event) {
          if (event.matches) {
            setOpen(false);
          }
        });
      }
    }
  }

  function initTabs() {
    var groups = document.querySelectorAll('[data-tabs]');

    Array.prototype.forEach.call(groups, function (group) {
      var list = group.querySelector('[data-tablist]');
      var tabs = Array.prototype.slice.call(group.querySelectorAll('[data-tab]'));
      if (!list || !tabs.length) {
        return;
      }

      var panels = tabs.map(function (tab) {
        return document.getElementById(tab.getAttribute('data-tab'));
      });

      function select(index, moveFocus) {
        tabs.forEach(function (tab, i) {
          var selected = i === index;
          tab.setAttribute('aria-selected', selected ? 'true' : 'false');
          tab.setAttribute('tabindex', selected ? '0' : '-1');
          if (panels[i]) {
            panels[i].hidden = !selected;
          }
        });
        if (moveFocus) {
          tabs[index].focus();
        }
      }

      list.setAttribute('role', 'tablist');
      tabs.forEach(function (tab, i) {
        tab.setAttribute('role', 'tab');
        if (panels[i]) {
          tab.setAttribute('aria-controls', panels[i].id);
          panels[i].setAttribute('role', 'tabpanel');
          panels[i].setAttribute('aria-labelledby', tab.id);
        }

        tab.addEventListener('click', function () {
          select(i, false);
        });

        tab.addEventListener('keydown', function (event) {
          var next = null;
          if (event.key === 'ArrowRight') {
            next = (i + 1) % tabs.length;
          } else if (event.key === 'ArrowLeft') {
            next = (i - 1 + tabs.length) % tabs.length;
          } else if (event.key === 'Home') {
            next = 0;
          } else if (event.key === 'End') {
            next = tabs.length - 1;
          }
          if (next !== null) {
            event.preventDefault();
            select(next, true);
          }
        });
      });

      select(0, false);
    });
  }

  function legacyCopy(text) {
    return new Promise(function (resolve, reject) {
      var area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.className = 'visually-hidden';
      document.body.appendChild(area);
      area.select();
      var ok = false;
      try {
        ok = document.execCommand('copy');
      } catch (err) {
        ok = false;
      }
      document.body.removeChild(area);
      if (ok) {
        resolve();
      } else {
        reject(new Error('copy failed'));
      }
    });
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).catch(function () {
        return legacyCopy(text);
      });
    }
    return legacyCopy(text);
  }

  function initCopy() {
    var live = document.querySelector('[data-live]');
    var buttons = document.querySelectorAll('[data-copy]');

    function announce(message) {
      if (!live) {
        return;
      }
      live.textContent = '';
      window.setTimeout(function () {
        live.textContent = message;
      }, 50);
    }

    Array.prototype.forEach.call(buttons, function (button) {
      var block = button.closest('.code');
      var code = block ? block.querySelector('pre code') : null;
      var label = button.querySelector('[data-copy-label]');
      var timer = null;
      if (!code || !label) {
        return;
      }

      button.addEventListener('click', function () {
        copyText(code.textContent.replace(/\s+$/, '')).then(
          function () {
            label.textContent = 'Copied';
            button.classList.add('is-copied');
            announce('Copied to clipboard.');
            window.clearTimeout(timer);
            timer = window.setTimeout(function () {
              label.textContent = 'Copy';
              button.classList.remove('is-copied');
            }, 2000);
          },
          function () {
            announce('Copy failed. Select the text and copy it by hand.');
          }
        );
      });
    });
  }

  // Marks the header link of the section that is on screen with aria-current.
  function initSectionSpy() {
    var nav = document.getElementById('site-nav');
    if (!nav || !('IntersectionObserver' in window)) {
      return;
    }

    var links = {};
    Array.prototype.forEach.call(nav.querySelectorAll('a[href^="#"]'), function (link) {
      links[link.getAttribute('href').slice(1)] = link;
    });

    var sections = Array.prototype.slice.call(document.querySelectorAll('main > section[id]'));
    if (!sections.length) {
      return;
    }
    var onScreen = sections.map(function () {
      return false;
    });

    function update() {
      var current = null;
      sections.forEach(function (section, i) {
        if (onScreen[i]) {
          current = section.id;
        }
      });
      Object.keys(links).forEach(function (id) {
        if (id === current) {
          links[id].setAttribute('aria-current', 'location');
        } else {
          links[id].removeAttribute('aria-current');
        }
      });
    }

    // A thin band a little above the middle of the window decides which
    // section counts as the one being read.
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        onScreen[sections.indexOf(entry.target)] = entry.isIntersecting;
      });
      update();
    }, { rootMargin: '-35% 0px -60% 0px', threshold: 0 });

    sections.forEach(function (section) {
      observer.observe(section);
    });
  }

  // Reading-progress bar under the header, and the back-to-top link.
  function initScrollCues() {
    var bar = document.querySelector('[data-progress]');
    var toTop = document.querySelector('[data-to-top]');
    if (!bar && !toTop) {
      return;
    }
    var waiting = false;

    function update() {
      waiting = false;
      var page = document.documentElement;
      var y = window.pageYOffset || page.scrollTop || 0;
      var max = page.scrollHeight - window.innerHeight;
      if (bar) {
        var done = max > 0 ? Math.min(1, Math.max(0, y / max)) : 0;
        bar.style.transform = 'scaleX(' + done.toFixed(4) + ')';
      }
      if (toTop) {
        toTop.classList.toggle('is-visible', y > window.innerHeight * 0.9);
      }
    }

    function request() {
      if (!waiting) {
        waiting = true;
        window.requestAnimationFrame(update);
      }
    }

    window.addEventListener('scroll', request, { passive: true });
    window.addEventListener('resize', request);
    update();
  }

  // Shows a fade at the edge of a code block while more code lies that way,
  // and keeps a block in the tab order only when it actually scrolls.
  function initCodeScroll() {
    var blocks = document.querySelectorAll('.code');

    Array.prototype.forEach.call(blocks, function (block) {
      var pre = block.querySelector('pre');
      if (!pre) {
        return;
      }

      function update() {
        var max = pre.scrollWidth - pre.clientWidth;
        var scrolls = max > 4;
        block.classList.toggle('has-more-start', scrolls && pre.scrollLeft > 4);
        block.classList.toggle('has-more-end', scrolls && pre.scrollLeft < max - 4);
        if (pre.clientWidth > 0) {
          if (scrolls) {
            pre.setAttribute('tabindex', '0');
          } else {
            pre.removeAttribute('tabindex');
          }
        }
      }

      pre.addEventListener('scroll', update, { passive: true });
      if ('ResizeObserver' in window) {
        new ResizeObserver(update).observe(pre);
      } else {
        window.addEventListener('resize', update);
      }
      update();
    });
  }

  function init() {
    initTheme();
    initMenu();
    initTabs();
    initCopy();
    initSectionSpy();
    initScrollCues();
    initCodeScroll();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
