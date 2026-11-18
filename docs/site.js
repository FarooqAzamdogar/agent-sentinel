/* agent-sentinel site script: theme toggle, mobile menu, tabs, copy buttons.
   No dependencies and no network requests. The page works without it. */
(function () {
  'use strict';

  var root = document.documentElement;
  var THEME_KEY = 'agent-sentinel-theme';
  var THEME_COLORS = { dark: '#0b0f14', light: '#f6f7f9' };

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

  var stored = readStoredTheme();
  if (stored) {
    root.setAttribute('data-theme', stored);
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
      var metas = document.querySelectorAll('meta[name="theme-color"]');
      for (var i = 0; i < metas.length; i += 1) {
        metas[i].setAttribute('content', THEME_COLORS[next]);
      }
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

    function setOpen(open) {
      nav.classList.toggle('is-open', open);
      button.setAttribute('aria-expanded', open ? 'true' : 'false');
      button.setAttribute('aria-label', open ? 'Close menu' : 'Menu');
    }

    button.addEventListener('click', function () {
      var open = button.getAttribute('aria-expanded') !== 'true';
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

    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && button.getAttribute('aria-expanded') === 'true') {
        setOpen(false);
        button.focus();
      }
    });
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

  function init() {
    initTheme();
    initMenu();
    initTabs();
    initCopy();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
