// Every page works without this file. It adds progress on buttons, confirmation dialogs,
// live figures while a page is on screen and the wait after a restart.

// Show progress on the pressed button and swallow repeat presses until the next page arrives.
document.addEventListener('submit', function (event) {
  var form = event.target;
  if (event.defaultPrevented) return;
  var button = form.querySelector('button[type=submit]');
  if (!button) return;
  if (button.getAttribute('aria-busy') === 'true') {
    event.preventDefault();
    return;
  }
  button.setAttribute('aria-busy', 'true');
  // A download keeps this page open, so its button must come back by itself.
  if (form.hasAttribute('data-download')) {
    setTimeout(function () { button.removeAttribute('aria-busy'); }, 3000);
  }
});

// A page restored from the back/forward cache comes back exactly as it was left, spinner included.
window.addEventListener('pageshow', function (event) {
  if (!event.persisted) return;
  var busy = document.querySelectorAll('[aria-busy=true]');
  for (var i = 0; i < busy.length; i++) busy[i].removeAttribute('aria-busy');
  var confirmed = document.querySelectorAll('[data-confirmed]');
  for (var j = 0; j < confirmed.length; j++) confirmed[j].removeAttribute('data-confirmed');
});

// Destructive actions ask first. The dialog is built once and reused.
(function () {
  var dialog = null;
  var pending = null;

  function build() {
    dialog = document.createElement('dialog');
    dialog.className = 'confirm';
    dialog.setAttribute('aria-labelledby', 'confirm-title');
    dialog.innerHTML =
      '<form method="dialog"><h2 id="confirm-title"></h2><p class="muted" id="confirm-text"></p>' +
      '<div class="form-actions"><button class="btn btn-quiet" value="cancel">Cancel</button>' +
      '<button class="btn btn-danger" value="ok" id="confirm-ok"></button></div></form>';
    document.body.appendChild(dialog);
    dialog.addEventListener('close', function () {
      var form = pending;
      pending = null;
      if (form && dialog.returnValue === 'ok') {
        form.setAttribute('data-confirmed', '1');
        if (form.requestSubmit) { form.requestSubmit(); } else { form.submit(); }
      }
    });
  }

  document.addEventListener('submit', function (event) {
    var form = event.target;
    var question = form.getAttribute('data-confirm');
    if (!question || form.getAttribute('data-confirmed') === '1') return;
    if (!window.HTMLDialogElement) {
      if (!window.confirm(question)) event.preventDefault();
      return;
    }
    event.preventDefault();
    if (!dialog) build();
    pending = form;
    dialog.querySelector('#confirm-title').textContent = question;
    dialog.querySelector('#confirm-text').textContent = form.getAttribute('data-confirm-detail') || '';
    dialog.querySelector('#confirm-ok').textContent = form.getAttribute('data-confirm-button') || 'Continue';
    dialog.returnValue = '';
    dialog.showModal();
  }, true);
})();

// A checkbox or select that reveals the part of the form it controls.
(function () {
  function sync(control) {
    var target = document.getElementById(control.getAttribute('data-reveals'));
    // In a radio group only the chosen option decides.
    if (!target || (control.type === 'radio' && !control.checked)) return;
    var show = control.type === 'checkbox'
      ? control.checked
      : control.value === control.getAttribute('data-reveals-when');
    target.hidden = !show;
  }
  var controls = document.querySelectorAll('[data-reveals]');
  for (var i = 0; i < controls.length; i++) {
    sync(controls[i]);
    controls[i].addEventListener('change', function (event) { sync(event.target); });
  }
})();

// Live pages keep their figures current while on screen. Every endpoint answers with the
// same shape: text, chips, meters, levels and sparklines keyed by data attributes.
(function () {
  var live = document.querySelector('[data-live]');
  var interval = live ? Number(live.getAttribute('data-interval')) : 0;
  if (!live || !interval || !window.fetch) return;
  var timer = null;

  function each(values, selector, apply) {
    Object.keys(values || {}).forEach(function (key) {
      var nodes = document.querySelectorAll('[data-' + selector + '="' + key + '"]');
      for (var i = 0; i < nodes.length; i++) apply(nodes[i], values[key]);
    });
  }

  function refresh(data) {
    each(data.text, 'text', function (node, value) { node.textContent = value; });
    each(data.meter, 'meter', function (node, value) { node.value = value; });
    each(data.level, 'level', function (node, value) { node.className = 'tile level-' + value; });
    each(data.chip, 'chip', function (node, value) {
      node.className = 'chip chip-' + value.state;
      var label = node.querySelector('[data-chip-label]');
      if (label) label.textContent = value.label;
    });
    each(data.spark, 'spark', function (node, value) {
      node.querySelector('.spark-area').setAttribute('points', '0,28 ' + value.line + ' 100,28');
      node.querySelector('.spark-line').setAttribute('points', value.line);
      node.querySelector('.spark-now').setAttribute('points', value.now);
    });
  }

  function poll() {
    fetch(live.getAttribute('data-live'), {credentials: 'same-origin'}).then(function (response) {
      if (!response.ok) throw new Error(response.status);
      return response.json();
    }).then(function (data) {
      // Rendered before the first sample landed, so take the whole page once.
      if (live.getAttribute('data-ready') === '0' && data.ready) return location.reload();
      // Something changed that the page cannot patch in place, such as a PC added elsewhere.
      if (data.layout && live.getAttribute('data-layout') && data.layout !== live.getAttribute('data-layout')) {
        return location.reload();
      }
      live.classList.remove('is-stale');
      refresh(data);
    }).catch(function () {
      live.classList.add('is-stale');
    });
  }

  function start() {
    if (timer) return;
    timer = setInterval(poll, interval * 1000);
  }

  function stop() {
    clearInterval(timer);
    timer = null;
  }

  document.addEventListener('visibilitychange', function () {
    if (document.hidden) { stop(); } else { poll(); start(); }
  });
  if (!document.hidden) start();
})();

// After a restart, wait until the server answers again, then continue where it said.
(function () {
  var waiting = document.querySelector('[data-restart-health]');
  if (!waiting || !window.fetch) return;
  var health = waiting.getAttribute('data-restart-health');
  var target = waiting.getAttribute('data-restart-target');
  var status = document.querySelector('[data-restart-status]');
  var started = Date.now();

  function attempt() {
    // no-cors: after a port change the server lives at another origin; any answer at all
    // means it is back, and the next page load checks the rest.
    fetch(health + '?t=' + Date.now(), {mode: 'no-cors', cache: 'no-store'}).then(function () {
      location.href = target;
    }).catch(function () {
      if (Date.now() - started > 120000) {
        if (status) status.textContent = 'The server has not come back after two minutes. Check the launcher console on the device.';
        return;
      }
      setTimeout(attempt, 2000);
    });
  }
  setTimeout(attempt, 3000);
})();
