// ============================================================
// components/layout/Sidebar.tsx
// ============================================================
import React, { useState } from "react";
import { NavLink, useLocation } from "react-router-dom";

const NAV = [
  { to: "/",           label: "Overview",      icon: "◈", tag: "M9"  },
  { to: "/ids",        label: "IDS Monitor",   icon: "◉", tag: "M1/M3" },
  { to: "/incidents",  label: "Incidents",     icon: "⚑", tag: "M7"  },
  { to: "/mitre",      label: "MITRE Matrix",  icon: "⊞", tag: "M6"  },
  { to: "/ml",         label: "ML Models",     icon: "◌", tag: "M2"  },
  { to: "/purple",     label: "Purple Team",   icon: "◆", tag: "M10" },
  { to: "/reports",    label: "Reports",       icon: "▤", tag: "—"   },
  { to: "/admin",      label: "Admin",         icon: "⊗", tag: "—"   },
];

export function Sidebar() {
  return (
    <aside style={{
      width: "var(--sidebar-w)",
      height: "100vh",
      background: "var(--cs-surface)",
      borderRight: "0.5px solid var(--cs-border)",
      display: "flex",
      flexDirection: "column",
      position: "fixed",
      top: 0, left: 0,
      zIndex: 100,
    }}>
      {/* Logo */}
      <div style={{
        padding: "18px 16px 14px",
        borderBottom: "0.5px solid var(--cs-border)",
      }}>
        <div style={{
          fontFamily: "'IBM Plex Mono', monospace",
          fontSize: "15px",
          fontWeight: 600,
          color: "var(--cs-text)",
          letterSpacing: "-.5px",
        }}>
          Cyber<span style={{ color: "var(--cs-blue)" }}>Sentinel</span>
        </div>
        <div style={{ fontSize: "10px", color: "var(--cs-text3)", marginTop: "2px", fontFamily: "monospace" }}>
          Purple Team v2.0
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, overflowY: "auto", padding: "8px 0" }}>
        {NAV.map(item => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === "/"}
            style={({ isActive }) => ({
              display: "flex",
              alignItems: "center",
              gap: "10px",
              padding: "8px 16px",
              textDecoration: "none",
              color: isActive ? "var(--cs-text)" : "var(--cs-text2)",
              background: isActive ? "var(--cs-surface2)" : "transparent",
              borderLeft: isActive
                ? "2px solid var(--cs-blue)"
                : "2px solid transparent",
              transition: "all .1s",
              fontSize: "12px",
            })}
          >
            <span style={{ fontSize: "13px", minWidth: "16px", textAlign: "center" }}>
              {item.icon}
            </span>
            <span style={{ flex: 1, fontWeight: 400 }}>{item.label}</span>
            <span style={{
              fontSize: "9px",
              fontFamily: "'IBM Plex Mono', monospace",
              color: "var(--cs-text3)",
              background: "var(--cs-surface2)",
              padding: "1px 5px",
              borderRadius: "3px",
            }}>
              {item.tag}
            </span>
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div style={{
        padding: "12px 16px",
        borderTop: "0.5px solid var(--cs-border)",
        fontSize: "10px",
        color: "var(--cs-text3)",
        fontFamily: "monospace",
      }}>
        UM6P · PFE 2024-2025
      </div>
    </aside>
  );
}