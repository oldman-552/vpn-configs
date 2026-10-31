const fs = require("fs");
class Element {
  constructor(attrs = {}, parent = null) { this.attrs = attrs; this.parentElement = parent; this.value = ""; }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
}
const listeners = {};
global.Element = Element;
global.window = global;
global.document = { addEventListener: (t, fn) => (listeners[t] = fn) };
const calls = [];
global.f = (...a) => calls.push(["f", ...a]);
global.g = (v) => calls.push(["g", v]);
global.h = () => calls.push(["h"]);
eval(fs.readFileSync(require("path").join(__dirname, "../../web-admin/events.js"), "utf8"));
const fire = (type, target) => listeners[type]({ type, target });

const btn = new Element({ "data-on": "click:f", "data-args": '["x",48,true]' });
fire("click", new Element({}, btn));                      // child click bubbles -> f
const inp = new Element({ "data-on": "input:g", "data-args": '["$value"]' }); inp.value = "hello";
fire("input", inp);                                        // g("hello")
const modal = new Element({ "data-on": "click-self:h" });
fire("click", new Element({}, modal));                     // child: h must NOT fire
fire("click", modal);                                      // h
fire("click", new Element({ "data-on": "click:f", "data-args": "not json" })); // ignored
fire("click", new Element({ "data-on": "click:doesNotExist" }));              // ignored
fire("change", btn);                                       // wrong event type: ignored
const got = JSON.stringify(calls), want = JSON.stringify([["f","x",48,true],["g","hello"],["h"]]);
console.log(got); console.log(got === want ? "PASS" : "FAIL"); process.exit(got === want ? 0 : 1);
