/* agent-sentinel site script: theme toggle, mobile menu, tabs, copy buttons,
   current-section highlight, reading progress, back to top, code-block fades,
   and the live panel under the hero. No dependencies. The page works
   without it.
   What it requests, and when: on the home page, as it loads, two GET
   requests to api.github.com, one for the repository's stars, forks and last
   push and one for the latest run of the tests on main, and none while this
   tab holds answers less than ten minutes old (in sessionStorage). Only after
   the visitor clicks "Show my weather" does it ask the browser for their
   location, and it sends it, rounded to two decimals (about 1 km), in one GET
   request to api.open-meteo.com; the location is kept nowhere. Requests carry
   no cookies and no referrer, and give up after 8 seconds. The clocks read
   the device's own time. Nothing else is requested; on the 404 page, nothing.
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

  // ---------- The live panel under the hero ----------

  var REPO_API = 'https://api.github.com/repos/FarooqAzamdogar/agent-sentinel';
  var RUNS_API = REPO_API + '/actions/workflows/tests.yml/runs?branch=main&per_page=1';
  var LIVE_CACHE_MS = 10 * 60 * 1000;
  var FETCH_TIMEOUT_MS = 8000;
  // What is kept of each GitHub answer, in GitHub's own names, so that a
  // cached answer is checked by the same code as a fresh one.
  var REPO_FIELDS = ['stargazers_count', 'forks_count', 'pushed_at'];
  var RUN_FIELDS = ['head_branch', 'status', 'conclusion', 'run_number', 'html_url', 'updated_at'];
  var GITHUB_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
  var RUN_PAGE = /^actions\/runs\/\d+$/;

  // A test run in words, and the color of its chip: mint passed, pink failed,
  // yellow not finished or waiting for a person. Any other value shows nothing.
  var RUN_STATUS = {
    queued: ['queued', 'ask'],
    requested: ['queued', 'ask'],
    pending: ['queued', 'ask'],
    waiting: ['waiting', 'ask'],
    in_progress: ['running', 'ask']
  };
  var RUN_CONCLUSION = {
    success: ['passed', 'ok'],
    failure: ['failed', 'bad'],
    timed_out: ['timed out', 'bad'],
    startup_failure: ['failed to start', 'bad'],
    action_required: ['needs approval', 'ask'],
    cancelled: ['cancelled', ''],
    skipped: ['skipped', ''],
    neutral: ['neutral', ''],
    stale: ['stale', '']
  };

  // Every WMO weather code Open-Meteo documents, in plain words.
  var WEATHER_WORDS = {
    0: 'Clear sky',
    1: 'Mainly clear',
    2: 'Partly cloudy',
    3: 'Overcast',
    45: 'Fog',
    48: 'Freezing fog',
    51: 'Light drizzle',
    53: 'Drizzle',
    55: 'Heavy drizzle',
    56: 'Light freezing drizzle',
    57: 'Heavy freezing drizzle',
    61: 'Light rain',
    63: 'Rain',
    65: 'Heavy rain',
    66: 'Light freezing rain',
    67: 'Heavy freezing rain',
    71: 'Light snow',
    73: 'Snow',
    75: 'Heavy snow',
    77: 'Snow grains',
    80: 'Light rain showers',
    81: 'Rain showers',
    82: 'Violent rain showers',
    85: 'Light snow showers',
    86: 'Heavy snow showers',
    95: 'Thunderstorm',
    96: 'Thunderstorm with light hail',
    97: 'Heavy thunderstorm',
    99: 'Thunderstorm with heavy hail'
  };

  // What the visitor is told when the browser gives no location, by the
  // error's code: 1 permission denied, 2 position unavailable, 3 timeout.
  var LOCATION_FAILURES = {
    1: 'Location access is blocked, so nothing was sent. Allow it for this site to see your weather.',
    2: 'Your browser could not tell where you are. Try again in a moment.',
    3: 'Finding your location took too long. Try again.'
  };

  var WEATHER_FAILURES = {
    network: 'The weather service could not be reached. Try again later.',
    timeout: 'The weather service took too long to answer. Try again.',
    limited: 'The weather service turned the request down. Try again later.',
    http: 'The weather service turned the request down. Try again later.',
    data: 'The weather service sent something unexpected. Try again later.'
  };

  function has(table, key) {
    return Object.prototype.hasOwnProperty.call(table, key);
  }

  function element(tag, className, text) {
    var node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text) {
      node.textContent = text;
    }
    return node;
  }

  // A failed request, by kind: limited (a 403 or 429 answer), http, network,
  // timeout, or data (not the JSON asked for).
  function failure(kind) {
    var err = new Error(kind);
    err.kind = kind;
    return err;
  }

  // GETs JSON without cookies or a referrer. It gives up after
  // FETCH_TIMEOUT_MS and aborts the request where the browser can.
  function getJson(address, init) {
    return new Promise(function (resolve, reject) {
      var controller = typeof AbortController === 'function' ? new AbortController() : null;
      var timer = window.setTimeout(function () {
        reject(failure('timeout'));
        if (controller) {
          controller.abort();
        }
      }, FETCH_TIMEOUT_MS);
      init.credentials = 'omit';
      init.referrerPolicy = 'no-referrer';
      if (controller) {
        init.signal = controller.signal;
      }
      window.fetch(address, init).then(function (response) {
        if (response.status === 403 || response.status === 429) {
          throw failure('limited');
        }
        if (!response.ok) {
          throw failure('http');
        }
        return response.json().catch(function () {
          throw failure('data');
        });
      }).then(function (data) {
        window.clearTimeout(timer);
        resolve(data);
      }, function (err) {
        window.clearTimeout(timer);
        reject(err && err.kind ? err : failure('network'));
      });
    });
  }

  function readCached(key) {
    try {
      var entry = JSON.parse(window.sessionStorage.getItem(key));
      var age = Date.now() - entry.at;
      return age >= 0 && age < LIVE_CACHE_MS ? entry : null;
    } catch (err) {
      return null;
    }
  }

  function writeCached(key, entry) {
    entry.at = Date.now();
    try {
      window.sessionStorage.setItem(key, JSON.stringify(entry));
    } catch (err) {
      /* Storage can be blocked or full. The next page asks GitHub again. */
    }
  }

  // GitHub's answer for one address: this tab's copy while it is under ten
  // minutes old, otherwise one request. keep() returns what to cache of a
  // good answer, or null. A rate limit is cached too, so the page does not
  // ask again while it is likely to last.
  function askGitHub(key, address, keep) {
    var cached = readCached(key);
    if (cached) {
      return cached.limited ? Promise.reject(failure('limited')) : Promise.resolve(cached.data);
    }
    return getJson(address, { headers: { Accept: 'application/vnd.github+json' } }).then(function (data) {
      var kept = keep(data);
      if (!kept) {
        throw failure('data');
      }
      writeCached(key, { data: kept });
      return kept;
    }, function (err) {
      if (err.kind === 'limited') {
        writeCached(key, { limited: true });
      }
      throw err;
    });
  }

  function pick(source, names) {
    var kept = {};
    names.forEach(function (name) {
      kept[name] = source[name];
    });
    return kept;
  }

  // A whole number, not negative.
  function isCount(value) {
    return typeof value === 'number' && isFinite(value) && value >= 0 && Math.floor(value) === value;
  }

  // A time as GitHub writes it, in milliseconds, or null.
  function readTime(value) {
    if (typeof value !== 'string' || !GITHUB_TIME.test(value)) {
      return null;
    }
    var time = Date.parse(value);
    return isFinite(time) ? time : null;
  }

  function readRepo(data) {
    if (!data || typeof data !== 'object') {
      return null;
    }
    var pushed = readTime(data.pushed_at);
    if (!isCount(data.stargazers_count) || !isCount(data.forks_count) || pushed === null) {
      return null;
    }
    return { stars: data.stargazers_count, forks: data.forks_count, pushed: pushed };
  }

  // The latest run of the tests on main. Its page must be a run page of this
  // repository, whose address is the one the stars link in the page names.
  function readRun(data, repository) {
    var runs = data && data.workflow_runs;
    var run = Array.isArray(runs) && runs.length ? runs[0] : null;
    if (!run || typeof run !== 'object' || run.head_branch !== 'main') {
      return null;
    }
    var finished = run.status === 'completed';
    var table = finished ? RUN_CONCLUSION : RUN_STATUS;
    var state = finished ? run.conclusion : run.status;
    var address = run.html_url;
    var updated = readTime(run.updated_at);
    if (!has(table, state) || !isCount(run.run_number) || run.run_number < 1 || updated === null ||
        typeof address !== 'string' || address.indexOf(repository + '/') !== 0 ||
        !RUN_PAGE.test(address.slice(repository.length + 1))) {
      return null;
    }
    return {
      words: table[state][0],
      tone: table[state][1],
      finished: finished,
      number: run.run_number,
      address: address,
      updated: updated
    };
  }

  var numbers = window.Intl && Intl.NumberFormat ? new Intl.NumberFormat('en') : null;
  var relative = window.Intl && Intl.RelativeTimeFormat ?
    new Intl.RelativeTimeFormat('en', { numeric: 'auto' }) : null;
  // The units "3 hours ago" may use, with their length in seconds, longest first.
  var AGO = [
    ['year', 31536000], ['month', 2592000], ['week', 604800],
    ['day', 86400], ['hour', 3600], ['minute', 60]
  ];

  function counted(value, one, many) {
    return (numbers ? numbers.format(value) : String(value)) + ' ' + (value === 1 ? one : many);
  }

  // "3 hours ago", or null where the browser has no words for it, or where
  // the time is ahead of this device's clock by more than two minutes.
  function ago(time) {
    var seconds = (Date.now() - time) / 1000;
    if (!relative || seconds < -120) {
      return null;
    }
    for (var i = 0; i < AGO.length; i += 1) {
      if (seconds >= AGO[i][1]) {
        return relative.format(-Math.floor(seconds / AGO[i][1]), AGO[i][0]);
      }
    }
    return 'just now';
  }

  // The exact time, in the visitor's own time zone and format.
  function exactTime(time) {
    try {
      return new Intl.DateTimeFormat(undefined, {
        year: 'numeric', month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit', timeZoneName: 'short'
      }).format(time);
    } catch (err) {
      return new Date(time).toString();
    }
  }

  function when(time) {
    var words = ago(time);
    if (words) {
      return words;
    }
    try {
      var date = new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
      return 'on ' + date.format(time);
    } catch (err) {
      return 'on ' + new Date(time).toDateString();
    }
  }

  // Stars, forks, the last push and the latest test run on main, from
  // GitHub's API when the page loads. Whatever cannot be checked is not
  // shown; if nothing can be, a plain "unavailable" takes its place.
  function initStats() {
    var part = document.querySelector('[data-stats]');
    if (!part) {
      return;
    }
    var wait = part.querySelector('[data-stats-wait]');
    var list = part.querySelector('[data-stats-list]');
    var repoLink = part.querySelector('[data-stats-repo]');
    var stars = part.querySelector('[data-stats-stars]');
    var forks = part.querySelector('[data-stats-forks]');
    var pushed = part.querySelector('[data-stats-pushed]');
    var runItem = part.querySelector('[data-stats-run-item]');
    var runLink = part.querySelector('[data-stats-run]');
    var runState = part.querySelector('[data-stats-run-state]');
    var runWord = part.querySelector('[data-stats-run-word]');
    var runNumber = part.querySelector('[data-stats-run-number]');
    var runAgo = part.querySelector('[data-stats-run-ago]');
    if (!wait || !list || !repoLink || !stars || !forks || !pushed ||
        !runItem || !runLink || !runState || !runWord || !runNumber || !runAgo) {
      return;
    }
    var repository = repoLink.getAttribute('href');

    function unavailable() {
      list.hidden = true;
      wait.hidden = false;
      wait.textContent = 'Live stats unavailable.';
    }

    if (!window.fetch || !window.Promise || !window.JSON) {
      unavailable();
      return;
    }

    var repoAnswer = askGitHub('agent-sentinel-live-repo', REPO_API, function (data) {
      return readRepo(data) ? pick(data, REPO_FIELDS) : null;
    });
    // The run is extra: without it, the other three still show.
    var runAnswer = askGitHub('agent-sentinel-live-run', RUNS_API, function (data) {
      return readRun(data, repository) ? { workflow_runs: [pick(data.workflow_runs[0], RUN_FIELDS)] } : null;
    }).then(function (data) {
      return readRun(data, repository);
    }, function () {
      return null;
    });

    Promise.all([repoAnswer, runAnswer]).then(function (answers) {
      var repo = readRepo(answers[0]);
      var run = answers[1];
      if (!repo) {
        throw failure('data');
      }

      function showTimes() {
        pushed.textContent = when(repo.pushed);
        if (run) {
          runAgo.textContent = (run.finished ? 'finished ' : 'updated ') + when(run.updated);
        }
      }

      stars.textContent = counted(repo.stars, 'star', 'stars');
      forks.textContent = counted(repo.forks, 'fork', 'forks');
      pushed.setAttribute('datetime', new Date(repo.pushed).toISOString());
      pushed.setAttribute('title', 'Last push: ' + exactTime(repo.pushed));
      if (run) {
        runLink.setAttribute('href', run.address);
        runLink.setAttribute('title', 'Run ' + run.number + ', last updated ' + exactTime(run.updated));
        runState.className = 'status' + (run.tone ? ' status--' + run.tone : '');
        Array.prototype.forEach.call(runState.querySelectorAll('[data-icon]'), function (icon) {
          if (icon.getAttribute('data-icon') === run.tone) {
            icon.removeAttribute('hidden');
          } else {
            icon.setAttribute('hidden', '');
          }
        });
        runWord.textContent = run.words;
        runNumber.textContent = '#' + run.number;
        runAgo.setAttribute('datetime', new Date(run.updated).toISOString());
        runAgo.setAttribute('title', exactTime(run.updated));
        runItem.hidden = false;
      }
      showTimes();
      wait.hidden = true;
      list.hidden = false;
      // "3 hours ago" stays true while the page stays open.
      window.setInterval(showTimes, 60000);
    }).catch(unavailable);
  }

  // The visitor's own time and time zone, and UTC, once a second. Nothing is
  // sent anywhere. The clock is not a live region: no tick is announced.
  function initClock() {
    var part = document.querySelector('[data-clock]');
    var local = part && part.querySelector('[data-clock-local]');
    var utc = part && part.querySelector('[data-clock-utc]');
    var zone = part && part.querySelector('[data-clock-zone]');
    if (!local || !utc) {
      return;
    }
    var format = null;
    var zoneName = '';
    try {
      format = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      zoneName = format.resolvedOptions().timeZone || '';
    } catch (err) {
      format = null;
    }
    if (zone) {
      zone.textContent = zoneName;
      zone.hidden = !zoneName;
    }
    var timer = null;

    function two(value) {
      return value < 10 ? '0' + value : String(value);
    }

    function hms(hours, minutes, seconds) {
      return two(hours) + ':' + two(minutes) + ':' + two(seconds);
    }

    function tick() {
      var now = new Date();
      local.textContent = format ? format.format(now) :
        hms(now.getHours(), now.getMinutes(), now.getSeconds());
      utc.textContent = hms(now.getUTCHours(), now.getUTCMinutes(), now.getUTCSeconds());
      window.clearTimeout(timer);
      // The next tick lands just after the next whole second.
      timer = window.setTimeout(tick, 1010 - now.getMilliseconds());
    }

    // A background tab's timers are slowed; catch up as soon as it is back.
    document.addEventListener('visibilitychange', function () {
      if (!document.hidden) {
        tick();
      }
    });
    tick();
  }

  function celsius(value) {
    var whole = Math.round(value);
    return (whole < 0 ? '\u2212' + -whole : String(whole)) + '\u00a0\u00b0C';
  }

  function fahrenheit(value) {
    var whole = Math.round(value * 9 / 5 + 32);
    return (whole < 0 ? '\u2212' + -whole : String(whole)) + '\u00a0\u00b0F';
  }

  // Open-Meteo states the unit of each value it sends. A value in a unit
  // other than the one asked for is not shown.
  function unitIs(units, name, expected) {
    return !units || units[name] === undefined || units[name] === expected;
  }

  function isReading(value, low, high) {
    return typeof value === 'number' && isFinite(value) && value >= low && value <= high;
  }

  // The current conditions, or null if the answer is not what was asked for.
  function readWeather(data) {
    var now = data && data.current;
    var units = data && data.current_units;
    if (!now || typeof now !== 'object' || (units !== undefined && (!units || typeof units !== 'object'))) {
      return null;
    }
    if (!unitIs(units, 'temperature_2m', '\u00b0C') || !unitIs(units, 'apparent_temperature', '\u00b0C') ||
        !unitIs(units, 'wind_speed_10m', 'km/h')) {
      return null;
    }
    if (!isReading(now.temperature_2m, -100, 100) || !isReading(now.apparent_temperature, -100, 100) ||
        !isReading(now.wind_speed_10m, 0, 500) || !isCount(now.weather_code) ||
        (now.is_day !== 0 && now.is_day !== 1)) {
      return null;
    }
    return {
      temperature: now.temperature_2m,
      feels: now.apparent_temperature,
      wind: now.wind_speed_10m,
      // A code Open-Meteo does not document is left out rather than guessed.
      sky: has(WEATHER_WORDS, now.weather_code) ? WEATHER_WORDS[now.weather_code] : '',
      day: now.is_day === 1
    };
  }

  // icons is the panel's inert <template> of a sun and a moon; a copy of one
  // goes in the day or night chip.
  function showWeather(out, weather, icons) {
    var period = weather.day ? 'day' : 'night';
    var chip = element('span', 'status', period);
    var icon = icons && icons.content ? icons.content.querySelector('[data-icon="' + period + '"]') : null;
    if (icon) {
      chip.insertBefore(icon.cloneNode(true), chip.firstChild);
    }
    var reading = element('p', 'live__reading');
    reading.appendChild(element('span', 'live__temp', celsius(weather.temperature)));
    reading.appendChild(element('span', '', fahrenheit(weather.temperature)));
    reading.appendChild(chip);
    var feels = 'feels like ' + celsius(weather.feels) + ' (' + fahrenheit(weather.feels) + ').';
    out.textContent = '';
    out.appendChild(reading);
    out.appendChild(element('p', 'live__more', weather.sky ? weather.sky + ', ' + feels : 'It ' + feels));
    out.appendChild(element('p', 'live__more', 'Wind ' + Math.round(weather.wind) + '\u00a0km/h (' +
      Math.round(weather.wind / 1.609344) + '\u00a0mph).'));
  }

  // The weather for where the visitor is, only when they ask for it. Their
  // location goes to Open-Meteo rounded to two decimals (about 1 km) and is
  // kept nowhere: not in storage, not in a cookie, not in the HTTP cache.
  function initWeather() {
    var part = document.querySelector('[data-weather]');
    var button = part && part.querySelector('[data-weather-button]');
    var out = part && part.querySelector('[data-weather-out]');
    var icons = part && part.querySelector('template[data-weather-icons]');
    if (!button || !out) {
      return;
    }
    var attempt = 0;

    function say(message) {
      out.textContent = '';
      out.appendChild(element('p', 'live__message', message));
    }

    // Reading the location and asking Open-Meteo both happen inside this
    // handler, and nothing in this script clicks for the visitor, so neither
    // can happen before they click.
    button.addEventListener('click', function onWeatherClick() {
      if (button.getAttribute('aria-disabled') === 'true') {
        return;
      }
      if (!navigator.geolocation || !window.fetch) {
        say('This browser cannot share your location, so the weather cannot be shown.');
        return;
      }
      attempt += 1;
      var mine = attempt;

      function finish(message) {
        if (mine !== attempt) {
          return;
        }
        if (message) {
          say(message);
        }
        button.removeAttribute('aria-disabled');
      }

      // A browser may never answer if its question is closed unanswered.
      var watchdog = window.setTimeout(function () {
        finish(LOCATION_FAILURES[3]);
        attempt += 1;
      }, 30000);

      button.setAttribute('aria-disabled', 'true');
      say('Finding your location\u2026');

      navigator.geolocation.getCurrentPosition(function (position) {
        window.clearTimeout(watchdog);
        if (mine !== attempt) {
          return;
        }
        var coords = position && position.coords;
        var latitude = coords ? Math.round(coords.latitude * 100) / 100 : NaN;
        var longitude = coords ? Math.round(coords.longitude * 100) / 100 : NaN;
        if (!(Math.abs(latitude) <= 90 && Math.abs(longitude) <= 180)) {
          finish('Your browser gave a location that could not be read. Try again.');
          return;
        }
        say('Asking Open-Meteo for the weather\u2026');
        getJson('https://api.open-meteo.com/v1/forecast?latitude=' + latitude.toFixed(2) +
          '&longitude=' + longitude.toFixed(2) +
          '&current=temperature_2m,apparent_temperature,weather_code,wind_speed_10m,is_day&timezone=auto',
          { cache: 'no-store' }).then(function (data) {
          var weather = readWeather(data);
          if (!weather) {
            throw failure('data');
          }
          if (mine === attempt) {
            showWeather(out, weather, icons);
          }
          finish('');
        }).catch(function (err) {
          finish(WEATHER_FAILURES[err && has(WEATHER_FAILURES, err.kind) ? err.kind : 'network']);
        });
      }, function (error) {
        window.clearTimeout(watchdog);
        var code = error && error.code;
        finish(LOCATION_FAILURES[has(LOCATION_FAILURES, code) ? code : 2]);
      }, { enableHighAccuracy: false, maximumAge: 600000, timeout: 15000 });
    });
  }

  function initLive() {
    var panel = document.querySelector('.live');
    if (!panel) {
      return;
    }
    initStats();
    initClock();
    initWeather();

    // The light blinks when the panel first comes into view.
    if (!('IntersectionObserver' in window)) {
      panel.classList.add('is-seen');
      return;
    }
    var observer = new IntersectionObserver(function (entries) {
      if (entries.some(function (entry) { return entry.isIntersecting; })) {
        panel.classList.add('is-seen');
        observer.disconnect();
      }
    });
    observer.observe(panel);
  }

  function init() {
    initTheme();
    initMenu();
    initTabs();
    initCopy();
    initSectionSpy();
    initScrollCues();
    initCodeScroll();
    initLive();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
