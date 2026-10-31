/**
 * events.js — CSP-safe event delegation (replaces inline on*="..." handlers).
 *
 * Markup:  <button data-on="click:saveThing" data-args='["id-1", 48]'>
 *   • data-on: one or more "event:functionName" pairs separated by spaces.
 *     Use "click-self" to fire only when the element itself (not a child) is clicked.
 *   • data-args: optional JSON array. "$value" = element.value, "$event" = the Event.
 * Only global functions (window[name]) are callable, so markup cannot run arbitrary code.
 */
(() => {
  function resolveArgs(el, ev) {
    let args = [];
    const raw = el.getAttribute("data-args");
    if (raw) {
      try { args = JSON.parse(raw); } catch (_) { return null; }
      if (!Array.isArray(args)) return null;
    }
    return args.map((a) => (a === "$value" ? el.value : a === "$event" ? ev : a));
  }

  function dispatch(ev) {
    let el = ev.target instanceof Element ? ev.target : null;
    while (el) {
      const spec = el.getAttribute && el.getAttribute("data-on");
      if (spec) {
        for (const pair of spec.trim().split(/\s+/)) {
          const [type, fnName] = pair.split(":");
          const matches = type === ev.type || (type === "click-self" && ev.type === "click" && ev.target === el);
          if (!matches) continue;
          const fn = window[fnName];
          const args = resolveArgs(el, ev);
          if (typeof fn === "function" && args) fn.apply(el, args);
          return;
        }
      }
      el = el.parentElement;
    }
  }

  for (const type of ["click", "change", "input"]) {
    document.addEventListener(type, dispatch);
  }
})();
