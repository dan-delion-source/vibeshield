---
name: VibeShield
description: A local research workspace for explainable security findings.
colors:
  paper: "#fff"
  canvas: "#f7f8f5"
  ink: "#26362e"
  body-ink: "#28372f"
  muted: "#65736a"
  secondary-text: "#596951"
  line: "#e5e9e2"
  accent: "#a64228"
  accent-hover: "#87351f"
  rail: "#172b24"
  focus: "#be6c4e"
  nav-text: "#b6c8bd"
  nav-active-bg: "#e6eedf"
  nav-active-text: "#1d3328"
  complete-text: "#3a703e"
  complete-bg: "#edf6e9"
  incomplete-text: "#8e5b18"
  incomplete-bg: "#fbf2df"
  running-text: "#2d6465"
  running-bg: "#e8f2f0"
  failed-text: "#a43229"
  failed-bg: "#fcefe9"
  severity-high: "#ae372b"
  severity-medium: "#a56919"
  severity-low: "#566e93"
  severity-info: "#697861"
  severity-unrated: "#726585"
typography:
  headline:
    fontFamily: "'Manrope Variable', sans-serif"
    fontSize: "30px"
    fontWeight: 650
    lineHeight: 1.35
    letterSpacing: "-.035em"
  title:
    fontFamily: "'Manrope Variable', sans-serif"
    fontSize: "16px"
    fontWeight: 700
    letterSpacing: "-.02em"
  body:
    fontFamily: "'Manrope Variable', sans-serif"
    fontSize: "14px"
    lineHeight: 1.7
  label:
    fontFamily: "'Manrope Variable', sans-serif"
    fontSize: "11px"
    fontWeight: 650
  evidence:
    fontFamily: "monospace"
    fontSize: "10px"
    lineHeight: 1.8
rounded:
  status: "4px"
  control: "7px"
  navigation: "8px"
  target-input: "9px"
  notice: "10px"
  panel: "14px"
spacing:
  control-gap: "9px"
  stage-gap: "18px"
  section-gap: "25px"
  main-gutter: "40px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.paper}"
    rounded: "{rounded.control}"
    padding: "0 16px"
    typography: "{typography.label}"
  button-primary-hover:
    backgroundColor: "{colors.accent-hover}"
  button-secondary:
    backgroundColor: "{colors.paper}"
    textColor: "#41513f"
    rounded: "{rounded.control}"
    padding: "0 16px"
  target-input:
    backgroundColor: "{colors.paper}"
    rounded: "{rounded.target-input}"
    padding: "5px 6px 5px 13px"
  navigation-active:
    backgroundColor: "{colors.nav-active-bg}"
    textColor: "{colors.nav-active-text}"
    rounded: "{rounded.navigation}"
    padding: "12px 14px"
  status-completed:
    backgroundColor: "{colors.complete-bg}"
    textColor: "{colors.complete-text}"
    rounded: "{rounded.status}"
    padding: "4px 6px"
  panel:
    backgroundColor: "{colors.paper}"
    rounded: "{rounded.panel}"
  evidence-block:
    backgroundColor: "#f4f6ef"
    textColor: "#5a6f50"
    rounded: "{rounded.control}"
    typography: "{typography.evidence}"
    padding: "13px"
---

# Design System: VibeShield

## Overview

**Creative North Star: "The Research Desk"**

A quiet research desk with paper surfaces, an ink-green navigation rail, and terracotta actions. Dense evidence tables use precise rules and restrained type so targets, findings, and coverage remain easy to compare.

This documents the implemented visual system in dashboard/web/src/style.css and main.jsx. The metaphor and descriptive color names are implementation assumptions, not user-confirmed brand preferences.

**Key Characteristics:**

- Paper surfaces with fine structural rules.
- One warm action accent against subdued green neutrals.
- Compact labels, explicit status text, and inspectable evidence.

## Colors

A warm terracotta action color sits within a pale paper and muted green system. Frontmatter values are authoritative; descriptive names below describe their use.

### Primary

- **Terracotta:** `accent` marks primary actions, selected target tabs, and running stage markers. `accent-hover` deepens enabled action hover.

### Neutral

- **Paper and canvas:** `paper` encloses working content; `canvas` separates it from the page.
- **Ink green:** `ink` and `body-ink` establish readable text; `rail` anchors navigation.
- **Sage-gray:** `muted` supports general secondary text; the darker `secondary-text` covers evidence metadata, table headings, placeholder text, scanner descriptions, and footer text. `line` creates structural divisions.
- **Pale leaf:** `nav-active-bg` and `nav-active-text` identify the current navigation destination.

### Semantic colors

Completed, incomplete, running, and failed states each have paired foreground and background tokens. Severity has its own high, medium, low, information, and unrated foregrounds. These are data signals, not additional brand accents; label every signal in text. The focus color marks keyboard interaction.

## Typography

Manrope Variable is bundled through the frontend font package and uses a sans-serif fallback. The page title uses the headline role; panel headings use title; actions use label. Target field labels, hints, permission text, input text, and target choices use 12px; target choices become 11px on mobile. The base is body, while the dense interface actually uses many smaller labels from 9–12px. Paragraph line height is inherited from the paragraph rule, not a global line-height declaration. Evidence uses the browser monospace stack.

Page headlines shrink to 27px at 980px and 25px at 760px. The inspection pane title is 23px with a 1.45 line height, shrinking to 22px on mobile. Counts use tabular numerals. Long locations wrap in evidence views; compact target cells truncate rather than force the page wider.

## Layout

The desktop shell has a fixed 232px rail and a 77px top bar. The main region is centered within a 1450px maximum width with 40px side gutters. Composer and scanner readiness occupy a flexible column plus a 258px column, separated by 25px. Result tables span their containing paper panel.

At 1500px and above, main top spacing increases, the readiness column is 280px, and the composer gap is 35px. At 1180px and below, the rail becomes 210px and main gutters 26px; settings become one column. At 980px, the composer becomes one column and scanner readiness remains visible below it as a two-column list. At 760px, navigation moves off canvas, the header becomes 66px, gutters become 19px, and the target action fills a separate row. The mobile scan table retains a 610px minimum width and findings table 720px inside horizontal scroll containers.

## Elevation & Depth

Paper panels are flat, separated by fine borders and background tone. Shadows appear on the floating toast, the modal evidence pane, and the focused target field. The drawer backdrop adds a 2px blur.

- **Inspection pane:** `-16px 0 50px #1025181f` establishes a temporary foreground layer.
- **Toast:** `0 8px 32px #1732202b` separates an ephemeral message from the workspace.
- **Target focus:** `0 0 0 3px #a86b5012` accompanies the input border change.

## Shapes

Panels have the broadest recurring corner treatment. Controls and navigation use tighter curves; status pills are compact rounded rectangles rather than capsules. Tiny round dots accompany severity and local status. Ruled tables and stage connectors provide alignment; there are no decorative gradients or raster textures in the implemented dashboard.

## Components

### Buttons

Primary actions use terracotta with white text; secondary actions use paper with a pale border and green text. Standard buttons have a 41px minimum height. The composer action is 37px on desktop and 42px on mobile. Disabled controls use half opacity and a not-allowed cursor. Background, color, and shadow transition over 0.17s with ease. Text actions gain an underline on hover.

### Inputs / Fields

The target field groups an icon, input, and submit action within one bordered container. Target choices are a labeled button group with `aria-pressed` selection, and wrap on mobile. Focus within shifts the border and applies the target focus shadow. Invalid input gets a red border and a separate error message. Search inputs and selects remain compact, with accessible labels supplied by the React markup. Most keyboard controls use a 3px focus outline with a 4px offset; the target text input instead relies on its container focus treatment.

### Navigation

Navigation uses compact icon-and-label rows in the dark rail. The active row has a pale background and heavier text; hover brightens the row. Mobile exposes an opening button and a backdrop close target. The closed rail uses hidden visibility to remove its controls from keyboard navigation; it opens without a transition. The workspace identity is static and has no dropdown indicator.

### Chips and states

Scan state badges pair an icon, readable label, and semantic color pair. Source tags are bordered neutral rectangles. Severity pairs a colored dot with text; unrated remains a distinct status. These components communicate actual scanner data.

### Cards / Containers

Paper panels have a single fine rule and no resting shadow. Composer padding is 25px 26px before its footer; ledger headings use 22px 25px; settings use 26px. Each adapts at the documented breakpoints. Tables use light header tone, ruled rows, and a subtle row hover.

### Evidence inspection

The native dialog opens against the right edge at 550px wide, constrained to the viewport. It presents state, title, affected location, observation, source evidence, and rule reference in that order. Code blocks preserve whitespace and wrap long content. The close button, backdrop interaction, and Escape dismissal support returning to the results.

### Scan stages and notifications

Stage rows combine a status marker, name, result text, and thin connectors. Running indicators rotate over 1.4s linearly; there is no fabricated progress percentage. Reduced-motion preference disables all animations and transitions. Toasts sit near the bottom center of the content region and include a dismissal control.

## Do's and Don'ts

### Do:

- Do reuse paper panels, ink text, and terracotta primary actions.
- Do pair status and severity colors with readable labels.
- Do preserve visible keyboard focus and reduced-motion behavior.
- Do let evidence tables scroll within their container on narrow screens.

### Don't:

- Don't imply that a candidate is a confirmed exploit.
- Don't use invented counts or simulated scanner progress as decoration.
- Don't introduce a second display font or decorative card shadows into the current system.
