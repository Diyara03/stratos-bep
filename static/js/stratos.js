/* ============================================================
   Stratos BEP — Client-side Interactions
   Vanilla JS: tabs, flash messages, confirm modals, score bars
   ============================================================ */

document.addEventListener('DOMContentLoaded', function () {
  initTabs();
  initFlashMessages();
  initConfirmModals();
  initScoreBars();
});

/* --- Tabs --- */
function initTabs() {
  var buttons = document.querySelectorAll('.tab-btn');
  var panels = document.querySelectorAll('.tab-panel');
  if (!buttons.length) return;

  function activate(tabId) {
    buttons.forEach(function (btn) {
      btn.classList.toggle('tab-btn--active', btn.getAttribute('data-tab') === tabId);
    });
    panels.forEach(function (panel) {
      panel.classList.toggle('tab-panel--active', panel.getAttribute('data-tab') === tabId);
    });
  }

  buttons.forEach(function (btn) {
    btn.addEventListener('click', function () {
      var tabId = btn.getAttribute('data-tab');
      activate(tabId);
      history.replaceState(null, '', '#' + tabId);
    });
  });

  // Activate from URL hash or default to first tab
  var hash = window.location.hash.replace('#', '');
  var validTab = hash && document.querySelector('.tab-panel[data-tab="' + hash + '"]');
  if (validTab) {
    activate(hash);
  } else if (buttons.length) {
    activate(buttons[0].getAttribute('data-tab'));
  }
}

/* --- Flash Messages --- */
function initFlashMessages() {
  var flashes = document.querySelectorAll('.flash');
  flashes.forEach(function (flash) {
    // Auto-dismiss after 4 seconds
    var timer = setTimeout(function () {
      dismissFlash(flash);
    }, 4000);

    var btn = flash.querySelector('.flash__dismiss');
    if (btn) {
      btn.addEventListener('click', function () {
        clearTimeout(timer);
        dismissFlash(flash);
      });
    }
  });

  function dismissFlash(el) {
    el.classList.add('flash--fade-out');
    setTimeout(function () {
      el.remove();
    }, 300);
  }
}

/* --- Confirm Modals --- */
function initConfirmModals() {
  var forms = document.querySelectorAll('form[data-confirm]');
  if (!forms.length) return;

  // Create modal overlay once
  var overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML =
    '<div class="modal">' +
      '<h3 class="modal__title">Confirm Action</h3>' +
      '<p class="modal__text" id="modal-message"></p>' +
      '<div class="modal__actions">' +
        '<button type="button" class="btn btn--secondary" id="modal-cancel">Cancel</button>' +
        '<button type="button" class="btn btn--danger" id="modal-confirm">Confirm</button>' +
      '</div>' +
    '</div>';
  document.body.appendChild(overlay);

  var pendingForm = null;

  document.getElementById('modal-cancel').addEventListener('click', function () {
    overlay.classList.remove('modal-overlay--active');
    pendingForm = null;
  });

  document.getElementById('modal-confirm').addEventListener('click', function () {
    overlay.classList.remove('modal-overlay--active');
    if (pendingForm) {
      pendingForm.submit();
      pendingForm = null;
    }
  });

  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) {
      overlay.classList.remove('modal-overlay--active');
      pendingForm = null;
    }
  });

  forms.forEach(function (form) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      pendingForm = form;
      document.getElementById('modal-message').textContent = form.getAttribute('data-confirm');
      overlay.classList.add('modal-overlay--active');
    });
  });
}

/* --- Score Bars --- */
function initScoreBars() {
  var bars = document.querySelectorAll('.score-bar');
  bars.forEach(function (bar) {
    var score = parseInt(bar.getAttribute('data-score'), 10);
    if (isNaN(score)) return;
    score = Math.max(0, Math.min(100, score));

    var fill = bar.querySelector('.score-bar__fill');
    if (!fill) {
      fill = document.createElement('div');
      fill.className = 'score-bar__fill';
      bar.appendChild(fill);
    }

    fill.style.width = score + '%';

    // Color by threshold
    if (score < 25) {
      fill.className = 'score-bar__fill score-bar__fill--green';
    } else if (score < 70) {
      fill.className = 'score-bar__fill score-bar__fill--amber';
    } else {
      fill.className = 'score-bar__fill score-bar__fill--red';
    }
  });
}
