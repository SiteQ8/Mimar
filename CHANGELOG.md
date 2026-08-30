# Changelog

## 0.1.0

First release.

- A line based language for describing a system as trust zones, components
  (external entities, processes, and data stores), and the data flows between
  them, with encryption and authentication flags and a sensitive marker.
- STRIDE threat enumeration for every component and flow, using the standard
  mapping, each threat carrying a concrete first mitigation.
- Architecture weakness checks that look at the shape of the design: a sensitive
  store reachable from an untrusted zone, an external entity wired straight to a
  store, the most trusted zone one hop from untrusted ground, cleartext crossing
  a trust boundary, an unauthenticated flow into a more trusted zone, a sensitive
  flow left unencrypted, a sensitive store in a low trust zone, a flat design with
  no segmentation, and an external entity sharing a zone with a store. Each names
  the parts involved and the control that fixes it.
- A score and an A to F grade for the whole design.
- Reports in text, JSON, markdown, and HTML.
- A command line: analyze, example, serve, version. A non zero exit on any
  critical or high weakness for use in a pipeline.
- A browser version that draws a live trust layered architecture diagram and runs
  the same analysis, verified to match the Python engine exactly. Nothing is
  uploaded.
- Two example models, one with weaknesses and a hardened variant that scores full
  marks. 23 tests.
