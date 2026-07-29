/* ============================================================================
   phalanx.js — client-side polish
   ----------------------------------------------------------------------------
   Two responsibilities:

   1. Convert UTC ISO timestamps to the browser's local timezone, formatted
      nicely. Backend stores everything in UTC (correct). Views were rendering
      that raw, which looked ~hours wrong for non-UTC operators.

   2. Optional per-page auto-refresh. Views that benefit (Overview, Events,
      Network, Devices) opt in via body[data-auto-refresh="N"], where N is
      seconds. Pages without that attribute don't auto-refresh.

   Usage in views — replace
       @event.Timestamp.ToString("HH:mm:ss")
   with
       <span data-time-utc="@event.Timestamp.ToString("o")"
             data-time-format="time"></span>

   Where data-time-format ∈ {time, date, datetime, relative}
   ========================================================================= */
(function () {
    'use strict';

    // ── 1. Timestamp rendering ──────────────────────────────────────────────

    function pad(n) { return n < 10 ? '0' + n : String(n); }

    function fmtTime(d) {
        return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
    }

    function fmtDate(d) {
        return pad(d.getDate()) + '-' +
               pad(d.getMonth() + 1) + ' ' +
               String(d.getFullYear()).slice(2);
    }

    function fmtDateTime(d) {
        return pad(d.getDate()) + '-' + pad(d.getMonth() + 1) + ' ' + fmtTime(d);
    }

    function fmtRelative(d) {
        var secs = Math.floor((Date.now() - d.getTime()) / 1000);
        if (secs < 0)        return 'just now';
        if (secs < 5)        return 'just now';
        if (secs < 60)       return secs + 's ago';
        if (secs < 3600)     return Math.floor(secs / 60) + 'm ago';
        if (secs < 86400)    return Math.floor(secs / 3600) + 'h ago';
        if (secs < 86400*7)  return Math.floor(secs / 86400) + 'd ago';
        return fmtDate(d);
    }

    var formatters = {
        time:     fmtTime,
        date:     fmtDate,
        datetime: fmtDateTime,
        relative: fmtRelative
    };

    function renderTimes(root) {
        root = root || document;
        var nodes = root.querySelectorAll('[data-time-utc]');
        for (var i = 0; i < nodes.length; i++) {
            var el  = nodes[i];
            var raw = el.getAttribute('data-time-utc');
            if (!raw) continue;
            var d = new Date(raw);
            if (isNaN(d.getTime())) continue;

            var fmt = el.getAttribute('data-time-format') || 'time';
            var fn  = formatters[fmt] || formatters.time;
            el.textContent = fn(d);
            if (fmt === 'relative') el.title = d.toLocaleString();
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () { renderTimes(); });
    } else {
        renderTimes();
    }

    // Re-render relative timestamps every 30s so "2m ago" doesn't get stuck.
    setInterval(function () {
        var nodes = document.querySelectorAll('[data-time-utc][data-time-format="relative"]');
        for (var i = 0; i < nodes.length; i++) {
            var el = nodes[i];
            var d  = new Date(el.getAttribute('data-time-utc'));
            if (!isNaN(d.getTime())) el.textContent = fmtRelative(d);
        }
    }, 30000);

    window.phxRenderTimes = renderTimes;

    // ── 2. Auto-refresh ─────────────────────────────────────────────────────

    function safeSessionGet(key) {
        try {
            return sessionStorage.getItem(key);
        } catch (e) {
            return null;
        }
    }

    function safeSessionSet(key, value) {
        try {
            sessionStorage.setItem(key, value);
        } catch (e) {
            // Ignore storage restrictions; auto-refresh can still work.
        }
    }

    function safeSessionRemove(key) {
        try {
            sessionStorage.removeItem(key);
        } catch (e) {
            // Ignore storage restrictions; auto-refresh can still work.
        }
    }

    var body = document.body;
    var refreshSecs = body ? parseInt(body.getAttribute('data-auto-refresh') || '0', 10) : 0;
    if (refreshSecs > 0) {
        var scrollKey = 'phx-scroll-' + location.pathname;
        var saved     = safeSessionGet(scrollKey);
        if (saved !== null) {
            window.scrollTo(0, parseInt(saved, 10));
            safeSessionRemove(scrollKey);
        }

        setInterval(function () {
            // Don't reload mid-typing in form fields.
            var active = document.activeElement;
            if (active && (active.tagName === 'INPUT' ||
                           active.tagName === 'TEXTAREA' ||
                           active.tagName === 'SELECT')) {
                return;
            }
            safeSessionSet(scrollKey, String(window.scrollY));
            location.reload();
        }, refreshSecs * 1000);
    }
})();
