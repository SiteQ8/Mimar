# Mimar

**A security architecture tool.** Describe your system as trust zones, components, and the data flows between them, and Mimar draws the diagram and finds the threats: a STRIDE threat register for every component and flow, and the weaknesses in the shape of the architecture itself, each with the control that fixes it. It runs at design time, before anything is built, and it has zero dependencies.

Mimar means architect in Arabic. You describe the building; it inspects the plan.

**[Try it in your browser](https://siteq8.github.io/Mimar/)** with nothing to install. Edit the model and watch the diagram and the analysis update as you type. Nothing you enter leaves the page.

![Mimar analyzing a model in the browser](docs/screenshot.png)

## The idea

Most security problems in a system are decided before a line of code is written, in how the pieces are arranged. A database that the public internet can reach. A login that crosses the network in the clear. An admin path wired straight to the data with nothing checking it. These are architecture decisions, and the cheapest time to catch them is while the architecture is still a text file.

Mimar takes that text file. You write a short description of the system in a small language, and Mimar gives you three things:

1. **A diagram.** Trust zones as layered bands, components as shapes, and the data flows as arrows. Flows that touch a weakness are drawn in red, and unencrypted flows are dashed, so the risky parts stand out at a glance.
2. **A STRIDE threat register.** For every component and every flow, the threats that apply to it, Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, and Elevation of privilege, each with a first mitigation.
3. **Architecture weaknesses.** The higher value part: checks on the shape of the design, a sensitive store an untrusted zone can reach, cleartext crossing a trust boundary, an external entity with a direct line to the data, the most trusted zone one hop from hostile ground, a flat design with no segmentation. Each names the parts involved and the control that would fix it, and the whole model scores to a grade.

## Describe a system

The model is a short text file. Each line is one statement, and it reads close to plain notes.

```
name=Online shop

zone internet trust=0 label="Public internet"
zone dmz      trust=3 label="Public facing"
zone app      trust=6 label="Application"
zone data     trust=9 label="Restricted data"

entity  customer in internet label="Customer"
process web      in dmz      label="Web frontend"
process api      in app      label="Order API"
store   orders   in data     sensitive label="Customer orders"

flow customer -> web    proto=HTTPS encrypted authenticated label="Browse and buy"
flow web      -> api    proto=HTTP  label="Order requests"
flow api      -> orders proto=SQL   encrypted label="Read and write orders"
```

Zones have a **trust** level, where 0 is fully untrusted, such as the public internet, and higher numbers are more trusted. Components are an **entity** (a user or an outside system), a **process** (a service that does something), or a **store** (a place data rests, which you can mark **sensitive**). Flows are directed and can be marked **encrypted** and **authenticated**. Anything after a `#` is a comment.

## See the weaknesses

Run it over a model:

```
mimar analyze shop.mimar
```

The shop above has an admin flow that talks straight to the orders store over an unencrypted connection from an untrusted zone. Mimar scores it an F and explains why, most serious first:

```
Mimar threat model: Online shop
  score 0/100  grade F
  4 zones, 6 components, 5 flows
  8 architecture weaknesses, 39 STRIDE threats

Architecture weaknesses  (most serious first)
  [CRITICAL] Sensitive data store reachable from an untrusted zone
      The store Customer orders holds sensitive data, yet Administrator in an
      untrusted zone can reach it directly. One compromised entry point then
      reaches the data.
      control: Place the store behind an application tier that mediates every
      access, and never expose it to the untrusted zone.
  [HIGH] Cleartext flow crosses a trust boundary
      ...
```

The repository includes `examples/shop.mimar` and a hardened variant, `examples/shop-hardened.mimar`, where the admin goes through a portal and every flow is encrypted and authenticated. The hardened version scores 100 and an A. Running both, side by side, is the fastest way to see what the tool rewards.

## Install and use

Mimar is pure Python with no dependencies. Clone the repository and run it in place:

```
git clone https://github.com/SiteQ8/Mimar.git
cd Mimar
python3 -m mimar analyze examples/shop.mimar
```

Or install it so the `mimar` command is on your path:

```
pip install .
```

Commands:

```
mimar analyze <file>            analyze a model and print its threat model
mimar analyze <file> --format markdown --output report.md
mimar analyze <file> --format html --output report.html
mimar analyze <file> --format json     machine readable output
mimar example                   print an example model to start from
mimar serve                     open the browser version locally
mimar version
```

`analyze` returns a non zero exit code when it finds anything critical or high, so it fits in a pipeline or a pre commit check.

Reports come in **text** (with color in a terminal), **markdown** for a pull request or a wiki, **HTML** for a self contained page you can share, and **JSON** for feeding another tool.

## The same engine in the browser

The browser version at [siteq8.github.io/Mimar](https://siteq8.github.io/Mimar/) runs the same analysis, ported to JavaScript and checked to produce the identical result on the example models. It draws the live diagram and updates as you edit. It is a single page with no build step and no network calls, so you can read every line, and it works offline once loaded.

## What it does and does not do

Mimar is meant to be honest about its limits.

- **It models what you describe.** The analysis is only as good as the model. If you leave out a flow or misjudge a trust level, Mimar cannot know. The value is in making the architecture explicit enough to reason about, and in catching the obvious mistakes reliably.
- **STRIDE is a checklist, not a proof.** The threat register is the standard STRIDE mapping applied to each element. It is a thorough prompt for what to consider, not an exhaustive or guaranteed list of every threat to your system.
- **The weakness checks are opinionated heuristics.** They encode common architecture mistakes and sensible defaults. They will not catch every design flaw, and on an unusual but sound design they may flag something that is fine in context. Read them as an informed second opinion, not a verdict.
- **It is design time, not runtime.** Mimar reasons about a description of a system. It does not scan a network, read your code, or test a running service. It is a companion to those tools, aimed at the stage before them.
- **It is defensive.** Every output points at a control or a better design. There is nothing here that helps attack a system.

## Why zero dependencies

The whole tool is standard library Python and one page of vanilla JavaScript. You can read all of it, it will still run in years, and a security tool that pulls in a long chain of packages is asking you to trust all of them. This one asks you to trust what you can see.

## License

MIT. See [LICENSE](LICENSE).
