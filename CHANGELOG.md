# Changelog

## 0.1.0

First release.

- A small line based language for describing a system as trust zones, components
  (external entities, processes, and data stores), and the data flows between
  them.
- STRIDE threat generation for every component and flow, using the standard
  mapping, with a first mitigation for each threat.
- Architecture weakness checks on the shape of the design: a sensitive store
  reachable from an untrusted zone, cleartext across a trust boundary, an
  external entity with direct data store access, the most trusted zone reachable
  from an untrusted one, an unauthenticated flow into a more trusted zone, a
  sensitive flow left unencrypted, a sensitive store in a low trust zone, a flat
  architecture with no segmentation, and an external entity sharing a zone with a
  data store.
- A risk grade from A to F derived from the weaknesses found.
- Reports in text, markdown, HTML, and JSON.
- A command line: analyze, example, serve, and version. A non zero exit code when
  anything critical or high is found.
- A browser version with a live architecture diagram and the same analysis
  engine, ported to JavaScript and verified to match the Python result on the
  example models.
- Two example models, one with weaknesses and a hardened variant that scores full
  marks.
- Zero dependencies. 23 tests.
