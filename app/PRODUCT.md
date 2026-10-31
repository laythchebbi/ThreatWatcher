# Product

## Register

product

## Users

One person per account: the owner or security lead of a company whose brand gets phished
(a startup founder, an IT lead at a mid-size firm, a security analyst). They add the
company's domains once, then mostly meet the product through an alert: an email, a Slack
or Teams message, often outside working hours. When they open the app, the job is to
answer three questions fast: what changed, how bad is it, and what do I do next.

## Product Purpose

Threat Watcher warns a customer while a phishing campaign against their brand is still
being prepared. A lookalike domain gets registered, pointed at a server, given a TLS
certificate and loaded with a copy of the login page; each step leaves a public trace.
The product watches those traces on a schedule, plus leak sites and breach data that
mention the company, and raises an event for each change, before any phishing email goes
out. Success: a customer learns about a lookalike from Threat Watcher days before their
staff or customers receive the phish, and trusts that every event is real and new.

## Brand Personality

An intelligence briefing, not a movie. The owner's words: "something like the FBI or
CIA". Read as: authoritative, procedural, exact. The interface speaks like a declassified
report: plain declarative sentences, facts in a fixed order, timestamps in UTC, every
claim traceable to its source (registrar, certificate log, DNS answer, leak page). Calm
under pressure; severity is stated, not shouted. The emotional goal at 2 a.m. is
"someone competent has already sorted this for me."

## Anti-references

- Generic SaaS dashboard: hero metrics, gradient accents, rounded card grids, marketing
  tone inside the app.
- Hacker movie terminal: green on black, matrix rain, skulls, glitch effects, fake
  "ACCESS GRANTED" theatre. Also no kitsch spy props: no "TOP SECRET" rubber stamps,
  no redaction bars used as decoration.
- Enterprise SIEM clutter (Splunk, QRadar): every widget at once, tiny type, no
  hierarchy, needs training to read.

## Design Principles

1. **Severity first, then time.** The worst open item is always the first thing seen;
   order carries meaning, decoration does not.
2. **Every claim shows its evidence.** A lookalike row states what was observed and
   where it came from, so the reader can trust it without clicking through.
3. **Change, not state.** The product speaks in events ("certificate issued 03:12 UTC"),
   because a quiet day must look quiet.
4. **Briefing voice.** Short declarative copy, no exclamation, no marketing words,
   jargon only where the reader needs the exact term.
5. **Dense but legible.** Analysts scan many rows; density is welcome as long as
   hierarchy and contrast make the scan effortless.

## Accessibility & Inclusion

WCAG 2.2 AA. Text contrast at least 4.5:1, visible keyboard focus on every control,
full keyboard use of tabs and row actions, reduced motion respected. Severity is never
carried by color alone: every severity also shows as a word or label.
