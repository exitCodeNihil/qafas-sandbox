// Minimal stroke icon set — 1.6px strokes, currentColor, 18px default.
import type { SVGProps } from "react";

const base = (p: SVGProps<SVGSVGElement>) => ({
  width: 18,
  height: 18,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.6,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  ...p,
});

export const IconDashboard = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <path d="M3 12l9-8 9 8M5 10v10h5v-6h4v6h5V10" />
  </svg>
);
export const IconKey = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <circle cx="7.5" cy="15.5" r="4.5" />
    <path d="M10.7 12.3 21 2M16 7l3 3M14 9l2 2" />
  </svg>
);
export const IconDeployment = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <path d="M4 6h6M4 12h10M4 18h6" />
    <circle cx="17.5" cy="6" r="2.5" />
    <circle cx="17.5" cy="18" r="2.5" />
  </svg>
);
export const IconEdge = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <circle cx="12" cy="12" r="9" />
    <path d="M3 12h18M12 3c2.5 2.4 3.8 5.6 3.8 9S14.5 18.6 12 21M12 3C9.5 5.4 8.2 8.6 8.2 12S9.5 18.6 12 21" />
  </svg>
);
export const IconPlus = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <path d="M12 5v14M5 12h14" />
  </svg>
);
export const IconCopy = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <rect x="9" y="9" width="11" height="11" rx="2" />
    <path d="M5 15V5a2 2 0 0 1 2-2h8" />
  </svg>
);
export const IconLogout = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3M10 17l-5-5 5-5M4 12h11" />
  </svg>
);
export const IconTrash = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <path d="M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M6 7l1 13h10l1-13" />
  </svg>
);
export const IconSun = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <circle cx="12" cy="12" r="4" />
    <path d="M12 2v2M12 20v2M4 12H2M22 12h-2M5 5l1.5 1.5M17.5 17.5 19 19M19 5l-1.5 1.5M6.5 17.5 5 19" />
  </svg>
);
export const IconMoon = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z" />
  </svg>
);
export const IconRequests = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <path d="M4 6h16M4 12h16M4 18h10" />
    <circle cx="19" cy="18" r="1.5" fill="currentColor" stroke="none" />
  </svg>
);
export const IconObservability = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <path d="M3 12h4l2-5 4 10 2-5h6" />
  </svg>
);

/**
 * Brand mark — one inbound node fanning out to three upstreams.
 * Recoloured onto Astryx tokens.
 */
export const IconSignal = (p: SVGProps<SVGSVGElement>) => (
  <svg width={22} height={22} viewBox="0 0 24 24" fill="none" aria-hidden {...p}>
    <path
      d="M4 12h4M8 12c4 0 4-6 8-6M8 12c4 0 4 6 8 6M8 12h8"
      stroke="var(--color-accent)"
      strokeWidth="1.6"
      strokeLinecap="round"
    />
    <circle cx="4" cy="12" r="2" fill="var(--color-accent)" />
    <circle cx="18" cy="6" r="1.8" fill="var(--color-icon-secondary)" />
    <circle cx="18" cy="12" r="1.8" fill="var(--color-icon-secondary)" />
    <circle cx="18" cy="18" r="1.8" fill="var(--color-icon-secondary)" />
  </svg>
);

/** Sliders — request settings; distinct from the theme toggle's sun glyph. */
export const IconSliders = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <path d="M4 7h10M18 7h2M4 12h4M12 12h8M4 17h10M18 17h2" />
    <circle cx="16" cy="7" r="2" />
    <circle cx="10" cy="12" r="2" />
    <circle cx="16" cy="17" r="2" />
  </svg>
);

// Alert triangle — security alerts, distinct from the other status glyphs.
export const IconAlertTriangle = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <path d="M12 3.5 21.5 20h-19L12 3.5z" />
    <path d="M12 10v4M12 17.5h.01" />
  </svg>
);

// Sessions: a play-head over a track, for the session/trace concept.
export const IconSessions = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <circle cx="12" cy="12" r="9" />
    <path d="M10 8.5v7l6-3.5-6-3.5z" fill="currentColor" stroke="none" />
  </svg>
);
export const IconShield = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <path d="M12 3l7 3v5.5c0 4.2-2.9 7.9-7 9.5-4.1-1.6-7-5.3-7-9.5V6l7-3z" />
    <path d="M9 12l2 2 4-4" />
  </svg>
);
export const IconSearch = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <circle cx="11" cy="11" r="7" />
    <path d="M21 21l-4.3-4.3" />
  </svg>
);
export const IconPlay = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <path d="M7 5.5v13l11-6.5-11-6.5z" fill="currentColor" stroke="none" />
  </svg>
);
export const IconPause = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <rect x="6" y="5" width="4" height="14" rx="1" fill="currentColor" stroke="none" />
    <rect x="14" y="5" width="4" height="14" rx="1" fill="currentColor" stroke="none" />
  </svg>
);
export const IconStop = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <rect x="6" y="6" width="12" height="12" rx="2" fill="currentColor" stroke="none" />
  </svg>
);
export const IconArchiveBox = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <rect x="3" y="4" width="18" height="4.5" rx="1" />
    <path d="M4.5 8.5V19a1 1 0 0 0 1 1h13a1 1 0 0 0 1-1V8.5" />
    <path d="M10 13h4" />
  </svg>
);
export const IconExternalLink = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <path d="M9 5h10v10M19 5 9.5 14.5M6 8v10h10" />
  </svg>
);
export const IconCheck = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <path d="M5 12.5l4.5 4.5L19 7" />
  </svg>
);
export const IconChevronDown = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <path d="M6 9l6 6 6-6" />
  </svg>
);
export const IconRocket = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <path d="M12 3c3 1.2 5 4 5 8 0 2-1 4-2 5l-3 3-3-3c-1-1-2-3-2-5 0-4 2-6.8 5-8z" />
    <circle cx="12" cy="10" r="1.6" fill="currentColor" stroke="none" />
    <path d="M9 16l-2.5 1.5L7 15M15 16l2.5 1.5L17 15" />
  </svg>
);
export const IconSnapshot = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <path d="M4 8l1.5-2.5h13L20 8" />
    <rect x="3" y="8" width="18" height="12" rx="2" />
    <circle cx="12" cy="14" r="3.2" />
  </svg>
);

/** Cube — the sandbox metaphor in the nav and empty states. */
export const IconCube = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <path d="M12 2.8 20.5 7v10L12 21.2 3.5 17V7L12 2.8z" />
    <path d="M3.5 7 12 11.6 20.5 7M12 11.6V21.2" />
  </svg>
);

export const IconClose = (p: SVGProps<SVGSVGElement>) => (
  <svg {...base(p)}>
    <path d="M6 6l12 12M18 6L6 18" />
  </svg>
);
