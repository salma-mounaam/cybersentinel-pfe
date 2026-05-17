// ============================================================
// App.tsx — Routing CyberSentinel
// ============================================================
import React, { Suspense, lazy } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Sidebar } from "./components/layout/Sidebar";
// @ts-ignore: side-effect import for CSS file
import "./index.css";

// Lazy loading des pages
const Overview    = lazy(() => import("./pages/Overview"));
const CodeScan    = lazy(() => import("./pages/CodeScan"));
const IDSMonitor  = lazy(() => import("./pages/IDSMonitor"));
const Incidents   = lazy(() => import("./pages/Incidents"));
const MITREMatrix = lazy(() => import("./pages/MITREMatrix"));
const MLModels    = lazy(() => import("./pages/MLModels"));
const PurpleTeam  = lazy(() => import("./pages/PurpleTeam"));
const Reports     = lazy(() => import("./pages/Reports"));
const Admin       = lazy(() => import("./pages/Admin"));

// ajoute-les seulement si ces fichiers existent déjà
const SASTPage    = lazy(() => import("./pages/SASTScanner"));
const DASTPage    = lazy(() => import("./pages/DASTSandbox"));
const CICDPage    = lazy(() => import("./pages/CICD"));
const ScanResultsPage = lazy(() => import("./pages/ScanResults"));



function PageFallback() {
  return (
    <div
      style={{
        padding: "48px",
        textAlign: "center",
        color: "var(--cs-text2)",
        fontFamily: "monospace",
        fontSize: "12px",
      }}
    >
      Chargement...
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <div style={{ display: "flex", height: "100vh", overflow: "hidden" }}>
        <Sidebar />
        <main
          style={{
            marginLeft: "var(--sidebar-w)",
            flex: 1,
            overflowY: "auto",
            padding: "24px",
            background: "var(--cs-bg)",
          }}
        >
          <Suspense fallback={<PageFallback />}>
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/scan-code" element={<CodeScan />} />

              <Route path="/ids" element={<IDSMonitor />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/mitre" element={<MITREMatrix />} />
              <Route path="/ml" element={<MLModels />} />
              <Route path="/purple" element={<PurpleTeam />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/admin" element={<Admin />} />

              {/* pages cibles utilisées par CodeScan */}
              <Route path="/sast" element={<SASTPage />} />
              <Route path="/dast" element={<DASTPage />} />
              <Route path="/cicd" element={<CICDPage />} />
              <Route path="/scan-results" element={<ScanResultsPage />} />
            </Routes>
          </Suspense>
        </main>
      </div>
    </BrowserRouter>
  );
}