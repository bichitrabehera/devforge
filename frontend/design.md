# Design System Specification: Hard-Edged Neo-Brutalist Bento UI

## 1. Design Philosophy & Aesthetic Direction
* **Paradigm:** Neo-Brutalist Grid / Hard-Edged Bento Architecture.
* **Core Principle:** Structural clarity over soft ornamentation. Hierarchy is established through crisp solid strokes, sharp geometry, and zero-blur offset elevation rather than diffused shadows, glassmorphism, or gradients.
* **Target Viewport:** Desktop-first (`full screen width`) designed for high-density operational dashboards, real-time monitoring, and multi-pane workflows.

---

## 2. Geometry, Borders & Elevation

### Borders & Strokes
* **Primary Container Stroke:** `2px solid` high-contrast dark border (`border-2`). Applied to outer cards, navigation rails, active buttons, modal shells, and input fields.
* **Internal Dividers:** `1px solid` border (`border`) used sparingly inside lists, tables, and stacked inspector groups to avoid visual noise.
* **Rule:** Zero borderless floating cards. Every distinct functional zone must be bounded by a crisp outline.

### Corner Radii
* **Cards, Panels & Inputs:** Sharp or micro-rounded corners (`0px` to `4px` / `rounded-none` to `rounded-sm`).
* **Buttons & Badges:** `2px` to `4px` (`rounded-sm`).
* **Avatars & Status Dots:** Strictly circular (`9999px` / `rounded-full`) to provide human/organic contrast against the rigid grid.

### Elevation & Shadows (Zero-Blur Offset)
* **Standard Card / Panel Shadow:** `4px 4px 0px 0px` solid dark fill (`shadow-[4px_4px_0px_#000]`).
* **Interactive / Active Control Shadow:** `2px 2px 0px 0px` solid dark fill (`shadow-[2px_2px_0px_#000]`).
* **Hover / Press Micro-Interaction:** On hover, translate `-1px, -1px` (or deepen shadow); on active click, translate `+2px, +2px` and collapse shadow to `0px` for a tactile mechanical button feel.

---

## 3. Macro Layout & Spatial Grid

### Viewport Shell (`100vh` App Frame)
* **Left Navigation Rail:** Fixed width (`240px–260px` / ~16%–18% of viewport), full height, separated from the workspace by a `2px` vertical border.
* **Main Workspace Canvas:** Fluid remaining width (`1fr`), scrollable or locked-height depending on the view mode, padded with `20px–24px` outer gutters.

### Top Utility Header (`60px–64px` Height)
Horizontal flex row aligned `space-between` with `12px` gaps:
1. **Sidebar Toggle Button:** Square `40px × 40px` icon trigger with `2px` border.
2. **Global Search Input:** Wide rectangular input (`40%–50%` width, `40px` height) with leading search icon and `2px` border.
3. **Action Cluster (Right-Aligned):**
   * Square `40px × 40px` notification/utility icon buttons featuring top-right overlapping circular counter badges (`18px × 18px`).
   * Primary rectangular CTA button (`height: 40px`, `padding: 0 16px`, bold label, `2px` border + hard offset shadow).

### Page Header & 4-Column KPI Strip
* **Header Block:** Large bold page title (`28px–32px`) stacked tightly above a single-line muted subtitle (`13px–14px`).
* **KPI Row:** CSS Grid `grid-template-columns: repeat(4, minmax(0, 1fr))` with `16px` gap.
  * **Card Anatomy:** Horizontal flex container (`padding: 16px`, `2px` border, `4px` offset shadow).
  * **Left Slot:** `44px × 44px` square icon container with `1.5px` border.
  * **Right Slot:** Stacked vertical block containing:
    1. Metric label (`12px`, medium weight).
    2. Primary value (`24px–28px`, extra-bold/black weight, tight line-height).
    3. Trend/delta indicator (`11px`, bold directional arrow + comparison label).

### Multi-Pane Workspace Split (Below KPI Row)
* **3-Pane Layout (Full Collaboration / Messaging / Triage):**
  * CSS Grid `grid-template-columns: 28% 1fr 28%` with `16px` gap.
  * **Pane 1 (Master List):** Search filter input, 3-tab segmented filter bar (`All`, `Unread`, `Mentions`) with inline count pills, and scrollable entity rows.
  * **Pane 2 (Active Canvas):** Sticky pane header (entity status + action icons), scrollable content/stream body, and pinned bottom input/composer bar.
  * **Pane 3 (Context Inspector):** Stacked vertical cards/sections (`Profile/Summary`, `Attachments/Artifacts`, `Participants/Metadata`, `Quick Actions`) separated by `1px` rules.
* **2-Pane Simplified Variant (Recommended for Rapid Prototyping):**
  * CSS Grid `grid-template-columns: 1fr 340px` (Main execution/visualization canvas + right-hand live inspector/activity stream).

---

## 4. Navigation & Information Architecture

### Sidebar Taxonomy
* **Brand Header:** Square logo mark (`32px × 32px`) paired with bold wordmark and subtle product sub-label.
* **Grouped Sections:** Navigation links grouped into logical categories (`MAIN`, `DATA`, `SYSTEM`) under uppercase micro-headers (`10px`, bold, `0.08em` tracking).
* **Nav Item States:**
  * *Inactive:* Full-width row (`height: 38px`), leading `18px` icon, `13px` medium label, transparent background, no border.
  * *Active:* High-contrast fill, `2px` solid border, `3px 3px 0px` hard shadow, bold label.
* **Pinned Sidebar Footer:**
  * User profile card (`2px` border, avatar, name, role title, overflow trigger).
  * Full-width `Log out` action button (`2px` border, leading exit icon) anchored at the bottom edge.

---

## 5. Typography & Density Rules

* **Font Stack:** Clean geometric sans-serif (`Inter`, `Space Grotesk`, `Plus Jakarta Sans`, or `DM Sans`) paired with a crisp monospace (`JetBrains Mono`) for metrics, timestamps, and IDs.
* **Scale & Weights:**
  * **Page Title:** `28px` / Weight `800` / Tracking `-0.02em`
  * **KPI Stat Value:** `26px` / Weight `800` / Tabular numerals (`font-variant-numeric: tabular-nums`)
  * **Section / Card Header:** `15px–16px` / Weight `700`
  * **Body / List Primary:** `13px–14px` / Weight `500–600`
  * **Micro Metadata / Timestamps:** `11px` / Weight `500`
  * **Sidebar Group Labels:** `10px` / Weight `700` / Uppercase / Tracking `0.08em`
* **Spacing Rhythm:** Base-4 grid (`4px`, `8px`, `12px`, `16px`, `20px`, `24px`). Keep internal card padding compact (`12px–16px`) so high data density feels structured rather than cramped.

---

## 6. Tailwind CSS Reference Tokens

Use these utility patterns to implement the structural rules consistently across components:

```css
/* Primary Neo-Brutalist Card */
.nb-card {
  @apply border-2 border-black rounded-sm shadow-[4px_4px_0px_#000] p-4;
}

/* Interactive Button / Active Pill */
.nb-btn {
  @apply border-2 border-black rounded-sm shadow-[2px_2px_0px_#000] px-3 py-1.5 font-semibold text-sm transition-transform active:translate-x-[2px] active:translate-y-[2px] active:shadow-none;
}

/* Text Input / Search Box */
.nb-input {
  @apply border-2 border-black rounded-sm px-3 py-2 text-sm focus:outline-none focus:shadow-[2px_2px_0px_#000];
}

/* Square Icon Badge */
.nb-icon-box {
  @apply w-11 h-11 border-2 border-black rounded-sm flex items-center justify-center shrink-0;
}
```