/* Mimar in the browser. The analysis engine is a faithful port of the Python
   core, verified to produce the same result. The diagram is drawn from the same
   model. Everything runs locally; nothing is uploaded. */
(function () {
  "use strict";
  var VERSION = "0.1.0";
  function el(t, c, h) { var e = document.createElement(t); if (c) e.className = c; if (h != null) e.innerHTML = h; return e; }
  function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }

  /* ---------- parser ---------- */
  function tokenize(line) {
    var out = [], i = 0, n = line.length;
    while (i < n) {
      while (i < n && /\s/.test(line[i])) i++;
      if (i >= n) break;
      var tok = "";
      if (line[i] === '"') {
        i++;
        while (i < n && line[i] !== '"') { tok += line[i]; i++; }
        i++;
      } else {
        while (i < n && !/\s/.test(line[i])) {
          if (line[i] === '"') { i++; while (i < n && line[i] !== '"') { tok += line[i]; i++; } i++; }
          else { tok += line[i]; i++; }
        }
      }
      out.push(tok);
    }
    return out;
  }
  function opts(tokens) {
    var o = {};
    tokens.forEach(function (tok) {
      if (tok.indexOf("=") >= 0) { var p = tok.split("="); o[p[0].toLowerCase()] = p.slice(1).join("="); }
      else o[tok.toLowerCase()] = true;
    });
    return o;
  }
  function parseModel(text) {
    var model = { name: "system", zones: {}, zoneOrder: [], elements: {}, elemOrder: [], flows: [] };
    var lines = text.split("\n");
    for (var ln = 0; ln < lines.length; ln++) {
      var line = lines[ln].split("#")[0].trim();
      if (!line) continue;
      var tokens = tokenize(line);
      var head = tokens[0].toLowerCase();
      if (head === "name" && line.indexOf("=") >= 0) { model.name = line.split("=").slice(1).join("=").trim().replace(/^"|"$/g, ""); continue; }
      if (head.indexOf("name=") === 0) { model.name = line.split("=").slice(1).join("=").trim().replace(/^"|"$/g, ""); continue; }
      if (head === "zone") {
        if (tokens.length < 2) throw new Error("line " + (ln + 1) + ": zone needs a name");
        var o = opts(tokens.slice(2));
        var zid = tokens[1];
        if (!model.zones[zid]) model.zoneOrder.push(zid);
        model.zones[zid] = { id: zid, trust: parseInt(o.trust || 0, 10) || 0, label: (o.label && o.label !== true) ? o.label : "" };
      } else if (head === "entity" || head === "process" || head === "store") {
        if (tokens.length < 4 || tokens[2].toLowerCase() !== "in") throw new Error("line " + (ln + 1) + ": expected '" + head + " <id> in <zone>'");
        var oo = opts(tokens.slice(4));
        var eid = tokens[1];
        if (!model.elements[eid]) model.elemOrder.push(eid);
        model.elements[eid] = { id: eid, kind: head, zone: tokens[3], sensitive: !!oo.sensitive, label: (oo.label && oo.label !== true) ? oo.label : "" };
      } else if (head === "flow") {
        var ai = tokens.indexOf("->");
        if (ai < 0) throw new Error("line " + (ln + 1) + ": a flow needs 'src -> dst'");
        if (ai < 2 || ai + 1 >= tokens.length) throw new Error("line " + (ln + 1) + ": a flow needs 'src -> dst'");
        var fo = opts(tokens.slice(ai + 2));
        model.flows.push({ src: tokens[ai - 1], dst: tokens[ai + 1], protocol: (fo.proto && fo.proto !== true) ? fo.proto : "", encrypted: !!fo.encrypted, authenticated: !!fo.authenticated, label: (fo.label && fo.label !== true) ? fo.label : "" });
      } else {
        throw new Error("line " + (ln + 1) + ": unknown statement '" + tokens[0] + "'");
      }
    }
    return model;
  }
  function elName(e) { return e.label || e.id; }
  function zoName(z) { return z.label || z.id; }
  function flName(f) { return f.label || (f.src + " to " + f.dst); }
  function zoneOf(model, id) { var e = model.elements[id]; return e ? model.zones[e.zone] : null; }

  /* ---------- STRIDE ---------- */
  var CATEGORIES = {
    S: ["Spoofing", "an attacker pretends to be someone or something they are not"],
    T: ["Tampering", "data or code is changed without authorization"],
    R: ["Repudiation", "an action is taken that cannot later be proven or traced"],
    I: ["Information disclosure", "data is exposed to someone who should not see it"],
    D: ["Denial of service", "the component is overwhelmed or made unavailable"],
    E: ["Elevation of privilege", "an attacker gains rights they should not have"]
  };
  var APPLIES = { entity: ["S", "R"], process: ["S", "T", "R", "I", "D", "E"], store: ["T", "R", "I", "D"], flow: ["T", "I", "D"] };
  var KIND_WORD = { entity: "external entity", process: "process", store: "data store", flow: "data flow" };
  var MIT = {
    "entity|S": "Authenticate the entity strongly, with multi factor where it matters.",
    "entity|R": "Log the entity's actions to a tamper evident audit trail.",
    "process|S": "Require authenticated identity for callers, and verify it on every request.",
    "process|T": "Validate all input and protect code and configuration integrity.",
    "process|R": "Write signed, time stamped logs that the process itself cannot quietly alter.",
    "process|I": "Enforce least privilege and return only the data a caller is entitled to.",
    "process|D": "Add rate limiting, timeouts, and resource quotas.",
    "process|E": "Separate privileges, drop them early, and check authorization on every action.",
    "store|T": "Restrict write access and use integrity checks on stored data.",
    "store|R": "Log access to the store and keep those logs outside the store.",
    "store|I": "Encrypt data at rest and enforce access control on every read.",
    "store|D": "Provision for load, back up, and isolate the store from untrusted traffic.",
    "flow|T": "Protect the flow with integrity, such as TLS, so it cannot be altered in transit.",
    "flow|I": "Encrypt the flow so its contents cannot be read in transit.",
    "flow|D": "Guard the endpoints with rate limiting and fail closed under overload."
  };
  function threat(kind, cat, tid, tname) {
    var full = CATEGORIES[cat][0], meaning = CATEGORIES[cat][1];
    return { id: cat + ":" + tid, category: cat, category_name: full, target: tid, target_name: tname, target_kind: kind,
      description: "The " + KIND_WORD[kind] + " " + tname + " is exposed to " + full.toLowerCase() + ", where " + meaning + ".",
      mitigation: MIT[kind + "|" + cat] };
  }
  function threatsFor(model) {
    var out = [];
    model.elemOrder.forEach(function (id) {
      var e = model.elements[id];
      APPLIES[e.kind].forEach(function (c) { out.push(threat(e.kind, c, e.id, elName(e))); });
    });
    model.flows.forEach(function (f, i) {
      APPLIES.flow.forEach(function (c) { out.push(threat("flow", c, "flow" + (i + 1), flName(f))); });
    });
    return out;
  }
  function strideCounts(threats) {
    var c = { S: 0, T: 0, R: 0, I: 0, D: 0, E: 0 };
    threats.forEach(function (t) { c[t.category]++; });
    return c;
  }

  /* ---------- weaknesses ---------- */
  var UNTRUSTED_MAX = 1;
  var SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  function finding(id, sev, title, why, control, involved) { return { id: id, severity: sev, title: title, why: why, control: control, involved: involved }; }
  function findWeaknesses(model) {
    var f = [], zones = model.zones, els = model.elements;
    function zt(zid) { var z = zones[zid]; return z ? z.trust : 0; }
    var tvals = model.zoneOrder.map(function (z) { return zones[z].trust; });
    var highest = tvals.length ? Math.max.apply(null, tvals) : 0;

    model.flows.forEach(function (fl, i) {
      var a = els[fl.src], b = els[fl.dst];
      if (!a || !b) return;
      var crosses = a.zone !== b.zone, st = zt(a.zone), dt = zt(b.zone), pair = [fl.src, fl.dst];
      if (b.kind === "store" && b.sensitive && st <= UNTRUSTED_MAX && st < dt)
        f.push(finding("exposed-sensitive-store-" + (i + 1), "critical", "Sensitive data store reachable from an untrusted zone",
          "The store " + elName(b) + " holds sensitive data, yet " + elName(a) + " in an untrusted zone can reach it directly. One compromised entry point then reaches the data.",
          "Place the store behind an application tier that mediates every access, and never expose it to the untrusted zone.", pair));
      if (a.kind === "entity" && b.kind === "store")
        f.push(finding("entity-to-store-" + (i + 1), "high", "External entity has direct data store access",
          "The external entity " + elName(a) + " connects straight to the data store " + elName(b) + ", with no application logic in between to check what it is allowed to do.",
          "Route the entity through a process that enforces authorization, and remove the direct path to the store.", pair));
      if (highest > 0 && dt === highest && st <= UNTRUSTED_MAX && crosses)
        f.push(finding("untrusted-to-crown-" + (i + 1), "high", "The most trusted zone is reachable from an untrusted zone",
          elName(a) + " sits in an untrusted zone but reaches " + elName(b) + " in the most trusted zone. A management or core plane should never be one hop from hostile ground.",
          "Separate the trusted zone with a gateway and a jump path, and deny direct access from low trust zones.", pair));
      if (crosses && !fl.encrypted)
        f.push(finding("cleartext-crossing-" + (i + 1), "high", "Cleartext flow crosses a trust boundary",
          "The flow " + flName(fl) + " moves between zones without encryption, so anyone on the path between them can read or change it.",
          "Encrypt the flow end to end, for example with TLS, wherever it leaves a zone.", pair));
      if (crosses && dt > st && !fl.authenticated)
        f.push(finding("unauth-inbound-" + (i + 1), "medium", "Unauthenticated flow enters a more trusted zone",
          "The flow " + flName(fl) + " enters a more trusted zone without authenticating the caller, so the zone trusts a request it has not verified.",
          "Require and verify authentication at the boundary before the request is accepted.", pair));
      if (!crosses && !fl.encrypted && ((b.kind === "store" && b.sensitive) || (a.kind === "store" && a.sensitive)))
        f.push(finding("sensitive-flow-cleartext-" + (i + 1), "medium", "Sensitive data flow is not encrypted",
          "The flow " + flName(fl) + " carries sensitive data in the clear. Even inside one zone, an attacker who gains a foothold can read it.",
          "Encrypt the flow so a foothold in the zone does not hand over the data.", pair));
    });

    model.elemOrder.forEach(function (id) {
      var e = els[id];
      if (e.kind === "store" && e.sensitive && zt(e.zone) <= UNTRUSTED_MAX)
        f.push(finding("sensitive-in-low-trust-" + e.id, "high", "Sensitive data store sits in a low trust zone",
          "The store " + elName(e) + " holds sensitive data but lives in a low trust zone, close to where attackers start.",
          "Move the store into a restricted zone with its own trust boundary and tight access control.", [e.id]));
    });

    var used = {}; model.elemOrder.forEach(function (id) { used[els[id].zone] = 1; });
    if (Object.keys(used).length === 1 && model.elemOrder.length >= 3) {
      var kinds = {}; model.elemOrder.forEach(function (id) { kinds[els[id].kind] = 1; });
      if (Object.keys(kinds).length >= 2)
        f.push(finding("flat-architecture", "medium", "Flat architecture with no trust segmentation",
          "Every component sits in a single zone, so there is no boundary to contain a breach. Once one part falls, the rest are equally exposed.",
          "Separate the system into zones by trust, for example a public tier, an application tier, and a restricted data tier.",
          model.elemOrder.slice().sort()));
    }

    model.elemOrder.forEach(function (id) {
      var e = els[id];
      if (e.kind === "store") {
        for (var j = 0; j < model.elemOrder.length; j++) {
          var other = els[model.elemOrder[j]];
          if (other.kind === "entity" && other.zone === e.zone) {
            f.push(finding("entity-store-same-zone-" + e.id, "medium", "External entity shares a zone with a data store",
              "The external entity " + elName(other) + " and the data store " + elName(e) + " are in the same zone, with no boundary between an outsider and the data.",
              "Put the store in its own restricted zone, separated from any zone an external entity lives in.", [other.id, e.id]));
            break;
          }
        }
      }
    });

    f.sort(function (a, b) {
      var av = a.severity in SEV_ORDER ? SEV_ORDER[a.severity] : 9;
      var bv = b.severity in SEV_ORDER ? SEV_ORDER[b.severity] : 9;
      return av - bv;
    });
    return f;
  }

  /* ---------- analyze ---------- */
  var WEIGHT = { critical: 30, high: 15, medium: 7, low: 3, info: 0 };
  function grade(score) { return score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F"; }
  function analyze(model) {
    var findings = findWeaknesses(model), threats = threatsFor(model);
    var score = 100; findings.forEach(function (f) { score -= (WEIGHT[f.severity] || 0); }); score = Math.max(0, score);
    var sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(function (f) { sev[f.severity]++; });
    var kinds = { entity: 0, process: 0, store: 0 };
    model.elemOrder.forEach(function (id) { kinds[model.elements[id].kind]++; });
    return { name: model.name, weaknesses: findings, threats: threats, stride_counts: strideCounts(threats),
      summary: { zones: model.zoneOrder.length, elements: model.elemOrder.length, flows: model.flows.length,
        entities: kinds.entity, processes: kinds.process, stores: kinds.store,
        threats: threats.length, weaknesses: findings.length, severity: sev, score: score, grade: grade(score) } };
  }

  /* ---------- diagram ---------- */
  var KIND_FILL = { entity: "#5a86ff", process: "#3fd6c8", store: "#a78bff" };
  function worstFlowSeverity(model, fl) {
    // match weaknesses whose involved pair is exactly [src,dst]
    var fs = findWeaknesses(model), worst = null;
    fs.forEach(function (w) {
      if (w.involved.length === 2 && w.involved[0] === fl.src && w.involved[1] === fl.dst) {
        if (worst === null || SEV_ORDER[w.severity] < SEV_ORDER[worst]) worst = w.severity;
      }
    });
    return worst;
  }
  function drawDiagram(model) {
    var W = 720, padX = 16, zoneGap = 14, bandH = 92, headH = 22;
    var zonesSorted = model.zoneOrder.map(function (z) { return model.zones[z]; })
      .sort(function (a, b) { return a.trust - b.trust; });
    var used = {}; model.elemOrder.forEach(function (id) { used[model.elements[id].zone] = 1; });
    zonesSorted = zonesSorted.filter(function (z) { return used[z.id]; });
    var H = padX * 2 + zonesSorted.length * bandH + (zonesSorted.length - 1) * zoneGap;
    if (zonesSorted.length === 0) { H = 80; }
    var pos = {}, svg = [];
    svg.push('<svg viewBox="0 0 ' + W + ' ' + H + '" xmlns="http://www.w3.org/2000/svg" font-family="-apple-system,Segoe UI,Roboto,Arial,sans-serif">');
    svg.push('<defs><marker id="arr" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto"><path d="M0,0 L7,3 L0,6 Z" fill="#8aa0c8"/></marker>' +
      '<marker id="arrR" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto"><path d="M0,0 L7,3 L0,6 Z" fill="#f2607a"/></marker>' +
      '<marker id="arrA" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto"><path d="M0,0 L7,3 L0,6 Z" fill="#ffcb61"/></marker></defs>');

    zonesSorted.forEach(function (z, zi) {
      var y = padX + zi * (bandH + zoneGap);
      svg.push('<rect x="' + padX + '" y="' + y + '" width="' + (W - 2 * padX) + '" height="' + bandH + '" rx="10" fill="#0e1320" stroke="#2c3a58"/>');
      svg.push('<text x="' + (padX + 12) + '" y="' + (y + 15) + '" fill="#7f8fb0" font-size="11">' + esc(zoName(z)) + '  &#183;  trust ' + z.trust + '</text>');
      var elems = model.elemOrder.map(function (id) { return model.elements[id]; }).filter(function (e) { return e.zone === z.id; });
      var ew = 128, eh = 42, gap = 18;
      var totalW = elems.length * ew + (elems.length - 1) * gap;
      var startX = Math.max(padX + 14, (W - totalW) / 2);
      elems.forEach(function (e, ei) {
        var ex = startX + ei * (ew + gap), ey = y + headH + 6;
        pos[e.id] = { x: ex + ew / 2, y: ey + eh / 2, w: ew, h: eh, top: ey, bottom: ey + eh };
        var fill = KIND_FILL[e.kind];
        var shape = e.kind === "store"
          ? '<rect x="' + ex + '" y="' + ey + '" width="' + ew + '" height="' + eh + '" rx="4" fill="' + fill + '22" stroke="' + fill + '"/>'
          : e.kind === "entity"
            ? '<rect x="' + ex + '" y="' + ey + '" width="' + ew + '" height="' + eh + '" rx="21" fill="' + fill + '22" stroke="' + fill + '"/>'
            : '<rect x="' + ex + '" y="' + ey + '" width="' + ew + '" height="' + eh + '" rx="9" fill="' + fill + '22" stroke="' + fill + '"/>';
        svg.push(shape);
        var lbl = elName(e);
        if (lbl.length > 18) lbl = lbl.slice(0, 17) + "\u2026";
        svg.push('<text x="' + (ex + ew / 2) + '" y="' + (ey + eh / 2 + 1) + '" fill="#e8edf6" font-size="12" text-anchor="middle">' + esc(lbl) + '</text>');
        var badge = e.kind === "store" && e.sensitive ? "sensitive store" : KIND_WORD[e.kind];
        svg.push('<text x="' + (ex + ew / 2) + '" y="' + (ey + eh - 4) + '" fill="#8aa0c8" font-size="8.5" text-anchor="middle">' + esc(badge) + '</text>');
      });
    });

    // flows behind boxes would be ideal, but drawing after is fine with light lines
    model.flows.forEach(function (fl) {
      var a = pos[fl.src], b = pos[fl.dst];
      if (!a || !b) return;
      var sev = worstFlowSeverity(model, fl);
      var color = sev === "critical" || sev === "high" ? "#f2607a" : sev === "medium" ? "#ffcb61" : "#5b6d92";
      var marker = sev === "critical" || sev === "high" ? "url(#arrR)" : sev === "medium" ? "url(#arrA)" : "url(#arr)";
      var wdt = sev === "critical" || sev === "high" ? 2 : sev === "medium" ? 1.6 : 1.2;
      // connect from bottom of source to top of dest if going down, else nearest edges
      var x1 = a.x, y1 = a.y, x2 = b.x, y2 = b.y;
      if (b.top > a.bottom) { y1 = a.bottom; y2 = b.top - 2; }
      else if (a.top > b.bottom) { y1 = a.top; y2 = b.bottom + 2; }
      else { // same band: curve slightly
        y1 = a.top; y2 = b.top;
      }
      var dash = fl.encrypted ? "" : ' stroke-dasharray="5 3"';
      svg.push('<line x1="' + x1.toFixed(1) + '" y1="' + y1.toFixed(1) + '" x2="' + x2.toFixed(1) + '" y2="' + y2.toFixed(1) + '" stroke="' + color + '" stroke-width="' + wdt + '"' + dash + ' marker-end="' + marker + '"/>');
    });

    svg.push('</svg>');
    return svg.join("");
  }

  /* ---------- app ---------- */
  var EXAMPLES = {
    shop: 'name=Online shop\n\nzone internet trust=0 label="Public internet"\nzone dmz trust=3 label="Public facing"\nzone app trust=6 label="Application"\nzone data trust=9 label="Restricted data"\n\nentity customer in internet label="Customer"\nentity admin in internet label="Administrator"\nprocess web in dmz label="Web frontend"\nprocess api in app label="Order API"\nstore orders in data sensitive label="Customer orders"\nstore cache in app label="Session cache"\n\nflow customer -> web proto=HTTPS encrypted authenticated label="Browse and buy"\nflow web -> api proto=HTTP label="Order requests"\nflow api -> orders proto=SQL encrypted label="Read and write orders"\nflow api -> cache proto=redis label="Session lookups"\nflow admin -> orders proto=SQL label="Direct admin queries"\n',
    hardened: 'name=Online shop, hardened\n\nzone internet trust=0 label="Public internet"\nzone dmz trust=3 label="Public facing"\nzone app trust=6 label="Application"\nzone data trust=9 label="Restricted data"\n\nentity customer in internet label="Customer"\nentity admin in internet label="Administrator"\nprocess web in dmz label="Web frontend"\nprocess api in app label="Order API"\nprocess adminportal in app label="Admin portal"\nstore orders in data sensitive label="Customer orders"\nstore cache in app label="Session cache"\n\nflow customer -> web proto=HTTPS encrypted authenticated label="Browse and buy"\nflow web -> api proto=HTTPS encrypted authenticated label="Order requests"\nflow api -> orders proto=SQL encrypted authenticated label="Read and write orders"\nflow api -> cache proto=redis encrypted label="Session lookups"\nflow admin -> adminportal proto=HTTPS encrypted authenticated label="Admin sign in"\nflow adminportal -> orders proto=SQL encrypted authenticated label="Mediated admin queries"\n',
    flat: 'name=Flat design\n\nzone all trust=5 label="One big zone"\n\nentity user in all label="User"\nprocess app in all label="Monolith"\nstore db in all sensitive label="Everything"\n\nflow user -> app proto=HTTP label="Use the app"\nflow app -> db proto=SQL label="Store data"\n'
  };

  function render(model, err) {
    var out = document.getElementById("out");
    out.innerHTML = "";
    var errBox = document.getElementById("err");
    if (err) { errBox.textContent = err; errBox.style.display = "block"; } else { errBox.style.display = "none"; }
    if (!model) return;
    var r = analyze(model);
    var s = r.summary;

    var gradeClass = s.grade === "A" || s.grade === "B" ? "good" : s.grade === "C" ? "warn" : "bad";
    var bar = el("div", "scorebar");
    bar.appendChild(el("div", "grade " + gradeClass, esc(s.grade)));
    bar.appendChild(el("div", "scoremeta", "<b>" + s.score + " / 100</b><br>" + s.zones + " zones &middot; " + s.elements +
      " components &middot; " + s.flows + " flows<br>" + s.weaknesses + " architecture weaknesses &middot; " + s.threats + " STRIDE threats"));
    out.appendChild(bar);

    var diag = el("div", "diagram"); diag.innerHTML = drawDiagram(model); out.appendChild(diag);
    var legend = el("div", "legend",
      '<span><span class="dot" style="background:#5a86ff"></span>entity</span>' +
      '<span><span class="dot" style="background:#3fd6c8"></span>process</span>' +
      '<span><span class="dot" style="background:#a78bff"></span>data store</span>' +
      '<span><span class="dot" style="background:#f2607a"></span>flow with a weakness</span>' +
      '<span>dashed = not encrypted</span>');
    out.appendChild(legend);

    var wc = el("div"); wc.style.marginTop = "14px";
    wc.appendChild(el("h2", null, "Architecture weaknesses"));
    if (!r.weaknesses.length) wc.appendChild(el("div", "pill", "None found"));
    r.weaknesses.forEach(function (f) {
      var w = el("div", "w " + f.severity);
      w.innerHTML = '<div class="t"><span class="sev ' + f.severity + '">' + f.severity.toUpperCase() + '</span>' + esc(f.title) + '</div>' +
        '<div class="why">' + esc(f.why) + '</div><div class="ctl">Control: ' + esc(f.control) + '</div>';
      wc.appendChild(w);
    });
    out.appendChild(wc);

    var sc = el("div"); sc.style.marginTop = "14px";
    sc.appendChild(el("h2", null, "STRIDE threats"));
    var grid = el("div", "stride");
    ["S", "T", "R", "I", "D", "E"].forEach(function (c) {
      var cell = el("div", "scell");
      cell.innerHTML = '<div class="n">' + esc(CATEGORIES[c][0]) + '</div><div class="v">' + r.stride_counts[c] + '</div>';
      grid.appendChild(cell);
    });
    sc.appendChild(grid);
    var det = el("details");
    det.appendChild(el("summary", null, "See the full threat register (" + r.threats.length + ")"));
    var tbl = ['<table class="treg"><tr><th>Category</th><th>Component</th><th>First mitigation</th></tr>'];
    r.threats.forEach(function (t) { tbl.push("<tr><td>" + esc(t.category_name) + "</td><td>" + esc(t.target_name) + "</td><td>" + esc(t.mitigation) + "</td></tr>"); });
    tbl.push("</table>");
    det.appendChild(el("div", null, tbl.join("")));
    sc.appendChild(det);
    out.appendChild(sc);
  }

  function run() {
    var ta = document.getElementById("model");
    try { var m = parseModel(ta.value); render(m, null); }
    catch (e) { render(null, e.message); }
  }

  var debounce;
  window.addEventListener("load", function () {
    var v = document.getElementById("ver"); if (v) v.textContent = VERSION;
    var ta = document.getElementById("model");
    ta.value = EXAMPLES.shop;
    ta.addEventListener("input", function () { clearTimeout(debounce); debounce = setTimeout(run, 250); });
    document.getElementById("ex-shop").onclick = function () { ta.value = EXAMPLES.shop; run(); };
    document.getElementById("ex-hardened").onclick = function () { ta.value = EXAMPLES.hardened; run(); };
    document.getElementById("ex-flat").onclick = function () { ta.value = EXAMPLES.flat; run(); };
    run();
  });
  window.__MIMAR__ = { parseModel: parseModel, analyze: analyze, threatsFor: threatsFor, findWeaknesses: findWeaknesses, EXAMPLES: EXAMPLES };
})();
