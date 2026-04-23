# ============================================================
# M4 — Service SAST
# Orchestre Semgrep + Trivy + Gitleaks
# Parse SARIF → SASTFinding → PostgreSQL → M6 → M7
# ============================================================

import asyncio
import json
import logging
import os
import shutil
import tempfile
import zipfile
import uuid
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, unquote

from app.core.database import AsyncSessionLocal
from app.models.sast_finding import SASTFinding, SASTTool, SASTSeverity
from app.services.mitre_service import MitreEnrichmentEngine
from app.services.scoring_service import RiskScoringEngine

logger = logging.getLogger(__name__)


class SASTOrchestrator:
    """
    Orchestre les 3 outils SAST en parallèle.
    Parse leurs sorties SARIF/JSON et crée les findings en base.
    """

    SEMGREP_BIN = "/opt/semgrep-venv/bin/semgrep"
    TRIVY_BIN = "trivy"
    GITLEAKS_BIN = "gitleaks"

    def __init__(self):
        self.mitre_engine = MitreEnrichmentEngine()
        self.scoring_engine = RiskScoringEngine()

    async def run_full_scan(
        self,
        repo_path: str,
        repo_name: str = "",
        commit_sha: str = "",
        pr_number: Optional[int] = None
    ) -> dict:
        """
        Lance les 3 outils en parallèle et agrège les résultats.
        """
        scan_id = uuid.uuid4().hex
        repo_path = str(Path(repo_path).resolve())
        logger.info(f"M4 SAST scan démarré — {repo_path} | scan_id={scan_id}")

        if not Path(repo_path).exists():
            logger.error(f"Chemin de scan introuvable: {repo_path}")
            return {
                "scan_id": scan_id,
                "total": 0,
                "by_tool": {},
                "by_severity": {},
                "has_critical": False,
                "has_secrets": False,
                "saved_ids": [],
                "critical_incidents": 0,
                "error": f"Chemin introuvable: {repo_path}"
            }

        targets = self._resolve_scan_targets(repo_path)
        logger.info(
            "Cibles SAST | "
            f"semgrep={targets['semgrep']} | "
            f"trivy={targets['trivy']} | "
            f"gitleaks={targets['gitleaks']}"
        )

        semgrep_task = asyncio.create_task(self._run_semgrep(targets["semgrep"], repo_path))
        trivy_task = asyncio.create_task(self._run_trivy(targets["trivy"], repo_path))
        gitleaks_task = asyncio.create_task(self._run_gitleaks(targets["gitleaks"]))

        semgrep_findings, trivy_findings, gitleaks_findings = await asyncio.gather(
            semgrep_task,
            trivy_task,
            gitleaks_task,
            return_exceptions=True
        )

        all_findings = []

        for findings, tool in [
            (semgrep_findings, SASTTool.SEMGREP),
            (trivy_findings, SASTTool.TRIVY),
            (gitleaks_findings, SASTTool.GITLEAKS),
        ]:
            if isinstance(findings, Exception):
                logger.error(f"{tool.value} erreur: {findings}")
                continue

            for finding in findings:
                finding.repo_name = repo_name
                finding.commit_sha = commit_sha
                finding.pr_number = pr_number
                finding.scan_id = scan_id

                try:
                    technique_id = self.mitre_engine.resolve_sast({
                        "tool": tool.value,
                        "cwe": finding.cwe or ""
                    })
                    mitre_data = await self.mitre_engine.enrich_by_technique_id(technique_id)
                    finding.technique_id = mitre_data.get("technique_id")
                    finding.technique_name = mitre_data.get("technique_name")
                    finding.tactic = mitre_data.get("tactic")
                except Exception as e:
                    logger.warning(f"MITRE enrichissement échoué pour {tool.value}: {e}")

                all_findings.append(finding)

        saved_findings = await self._save_findings(all_findings)

        critical_count = 0
        for finding in saved_findings:
            try:
                if (
                    finding.severity == SASTSeverity.CRITICAL and
                    finding.cvss_score is not None and
                    float(finding.cvss_score) >= 9.0
                ):
                    incident = await self.scoring_engine.create_incident_from_sast(finding)
                    if incident:
                        critical_count += 1
            except Exception as e:
                logger.warning(f"Création incident échouée pour finding {getattr(finding, 'id', None)}: {e}")

        stats = self._compute_stats(saved_findings)
        stats["scan_id"] = scan_id
        stats["saved_ids"] = [f.id for f in saved_findings if getattr(f, "id", None) is not None]
        stats["critical_incidents"] = critical_count

        logger.info(
            f"M4 SAST terminé | "
            f"scan_id={scan_id} | "
            f"Total={stats['total']} | "
            f"Critique={stats['by_severity'].get('CRITICAL', 0)} | "
            f"Incidents créés={critical_count}"
        )

        return stats

    async def run_uploaded_scan(
        self,
        zip_path: str,
        repo_name: str = "",
        commit_sha: str = "",
        pr_number: Optional[int] = None,
    ) -> dict:
        """
        Extrait une archive ZIP temporaire, lance le scan SAST,
        puis supprime les fichiers temporaires.
        """
        zip_file = Path(zip_path)

        if not zip_file.exists():
            return {
                "total": 0,
                "by_tool": {},
                "by_severity": {},
                "has_critical": False,
                "has_secrets": False,
                "saved_ids": [],
                "critical_incidents": 0,
                "error": f"Archive introuvable: {zip_path}",
            }

        extract_dir = Path(tempfile.mkdtemp(prefix="sast_upload_"))

        try:
            with zipfile.ZipFile(zip_file, "r") as zf:
                zf.extractall(extract_dir)

            extracted_items = list(extract_dir.iterdir())
            if not extracted_items:
                return {
                    "total": 0,
                    "by_tool": {},
                    "by_severity": {},
                    "has_critical": False,
                    "has_secrets": False,
                    "saved_ids": [],
                    "critical_incidents": 0,
                    "error": "Le ZIP est vide après extraction.",
                }

            if len(extracted_items) == 1 and extracted_items[0].is_dir():
                scan_root = extracted_items[0]
            else:
                scan_root = extract_dir

            logger.info(f"SAST upload scan démarré — {scan_root}")

            result = await self.run_full_scan(
                repo_path=str(scan_root),
                repo_name=repo_name or zip_file.stem,
                commit_sha=commit_sha,
                pr_number=pr_number,
            )

            result["uploaded"] = True
            result["scan_root"] = str(scan_root)
            result["repo_name"] = repo_name or zip_file.stem
            return result

        except zipfile.BadZipFile:
            logger.error("Archive ZIP invalide")
            return {
                "total": 0,
                "by_tool": {},
                "by_severity": {},
                "has_critical": False,
                "has_secrets": False,
                "saved_ids": [],
                "critical_incidents": 0,
                "error": "Archive ZIP invalide.",
            }
        except Exception as e:
            logger.exception(f"Erreur run_uploaded_scan: {e}")
            return {
                "total": 0,
                "by_tool": {},
                "by_severity": {},
                "has_critical": False,
                "has_secrets": False,
                "saved_ids": [],
                "critical_incidents": 0,
                "error": f"Erreur scan upload: {str(e)}",
            }
        finally:
            try:
                if zip_file.exists():
                    zip_file.unlink(missing_ok=True)
            except Exception:
                pass

            try:
                shutil.rmtree(extract_dir, ignore_errors=True)
            except Exception:
                pass

    # ============================================================
    # Résolution de cibles
    # ============================================================

    def _resolve_scan_targets(self, repo_path: str) -> dict:
        repo = Path(repo_path)

        semgrep_target = repo
        preferred_dirs = ["app", "src", "lib", "routes", "frontend", "backend"]
        for candidate in preferred_dirs:
            candidate_path = repo / candidate
            if candidate_path.exists() and candidate_path.is_dir():
                semgrep_target = candidate_path
                break

        return {
            "repo": str(repo),
            "semgrep": str(semgrep_target),
            "trivy": str(repo),
            "gitleaks": str(repo),
        }

    # ============================================================
    # Semgrep
    # ============================================================

    async def _run_semgrep(self, repo_path: str, repo_root: str) -> list:
        logger.info("Semgrep démarré...")

        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
            sarif_path = tmp.name

        cmd = [
            self.SEMGREP_BIN,
            "--config", "p/owasp-top-ten",
            "--config", "p/python",
            "--config", "p/javascript",
            "--config", "p/typescript",
            "--sarif",
            "--output", sarif_path,
            "--quiet",
            "--exclude", "data",
            "--exclude", "reports",
            "--exclude", "__pycache__",
            "--exclude", ".pytest_cache",
            "--exclude", ".mypy_cache",
            "--exclude", "node_modules",
            "--exclude", ".git",
            "--exclude", "dist",
            "--exclude", "build",
            repo_path
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=420)

            logger.info(f"Semgrep returncode={proc.returncode}")
            if stdout:
                logger.debug(f"Semgrep stdout: {stdout.decode(errors='ignore')[:2000]}")
            if stderr:
                logger.warning(f"Semgrep stderr: {stderr.decode(errors='ignore')[:2000]}")

            return self._parse_sarif(sarif_path, SASTTool.SEMGREP, repo_root)

        except asyncio.TimeoutError:
            logger.error("Semgrep timeout (> 420s)")
            return []
        except FileNotFoundError:
            logger.error(f"Semgrep introuvable: {self.SEMGREP_BIN}")
            return []
        except Exception as e:
            logger.error(f"Semgrep erreur: {e}")
            return []
        finally:
            Path(sarif_path).unlink(missing_ok=True)

    # ============================================================
    # Trivy
    # ============================================================

    async def _run_trivy(self, repo_path: str, repo_root: str) -> list:
        logger.info("Trivy démarré...")

        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
            sarif_path = tmp.name

        cmd = [
            self.TRIVY_BIN, "fs",
            "--format", "sarif",
            "--output", sarif_path,
            "--severity", "CRITICAL,HIGH,MEDIUM",
            "--skip-dirs", "data",
            "--skip-dirs", "reports",
            "--skip-dirs", "__pycache__",
            "--skip-dirs", "node_modules",
            "--skip-dirs", ".git",
            "--skip-dirs", "dist",
            "--skip-dirs", "build",
            "--quiet",
            repo_path
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)

            logger.info(f"Trivy returncode={proc.returncode}")
            if stdout:
                logger.debug(f"Trivy stdout: {stdout.decode(errors='ignore')[:2000]}")
            if stderr:
                logger.warning(f"Trivy stderr: {stderr.decode(errors='ignore')[:2000]}")

            return self._parse_sarif(sarif_path, SASTTool.TRIVY, repo_root)

        except asyncio.TimeoutError:
            logger.error("Trivy timeout (> 180s)")
            return []
        except FileNotFoundError:
            logger.error("Trivy non installé")
            return []
        except Exception as e:
            logger.error(f"Trivy erreur: {e}")
            return []
        finally:
            Path(sarif_path).unlink(missing_ok=True)

    # ============================================================
    # Gitleaks
    # ============================================================

    async def _run_gitleaks(self, repo_path: str) -> list:
        logger.info("Gitleaks démarré...")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name

        repo = Path(repo_path)
        cmd = [
            self.GITLEAKS_BIN, "detect",
            "--source", str(repo),
            "--report-format", "json",
            "--report-path", report_path,
            "--no-banner",
            "--log-level", "error"
        ]

        if not (repo / ".git").exists():
            cmd.append("--no-git")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

            logger.info(f"Gitleaks returncode={proc.returncode}")
            if stdout:
                logger.debug(f"Gitleaks stdout: {stdout.decode(errors='ignore')[:2000]}")
            if stderr:
                logger.warning(f"Gitleaks stderr: {stderr.decode(errors='ignore')[:2000]}")

            return self._parse_gitleaks(report_path)

        except asyncio.TimeoutError:
            logger.error("Gitleaks timeout (> 120s)")
            return []
        except FileNotFoundError:
            logger.error("Gitleaks non installé")
            return []
        except Exception as e:
            logger.error(f"Gitleaks erreur: {e}")
            return []
        finally:
            Path(report_path).unlink(missing_ok=True)

    # ============================================================
    # Parsers SARIF + JSON
    # ============================================================

    def _parse_sarif(self, sarif_path: str, tool: SASTTool, repo_root: str) -> list:
        findings = []

        path = Path(sarif_path)
        if not path.exists() or path.stat().st_size == 0:
            logger.warning(f"SARIF vide ou absent: {sarif_path}")
            return []

        try:
            with open(sarif_path, "r", encoding="utf-8") as f:
                sarif = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning(f"SARIF parse erreur {sarif_path}: {e}")
            return []

        for run in sarif.get("runs", []):
            rules = {
                r["id"]: r
                for r in run.get("tool", {}).get("driver", {}).get("rules", [])
                if "id" in r
            }

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                rule = rules.get(rule_id, {})
                message = result.get("message", {}).get("text", "")
                level = result.get("level", "warning")
                severity = self._sarif_level_to_severity(level, rule)

                file_path = None
                line_start = None
                line_end = None
                col_start = None
                col_end = None
                code_snippet = None
                vulnerable_line = None

                locations = result.get("locations", [])
                if locations:
                    loc = locations[0].get("physicalLocation", {})
                    uri = loc.get("artifactLocation", {}).get("uri", "")
                    file_path = self._normalize_file_path(uri)

                    region = loc.get("region", {})
                    line_start = region.get("startLine")
                    line_end = region.get("endLine", line_start)
                    col_start = region.get("startColumn")
                    col_end = region.get("endColumn")

                    snippet = region.get("snippet", {})
                    if isinstance(snippet, dict):
                        code_snippet = snippet.get("text")

                    if not code_snippet and file_path and line_start:
                        full_path = self._resolve_file_on_disk(repo_root, file_path)
                        code_snippet, vulnerable_line = self._extract_code_snippet(
                            full_path, line_start, line_end
                        )
                    elif code_snippet:
                        vulnerable_line = self._extract_vulnerable_line_from_snippet(
                            code_snippet, line_start, line_end
                        )

                cwe = self._normalize_cwe(self._extract_cwe(rule))
                cve = self._extract_cve(rule, result)
                cvss = self._extract_cvss(rule, result, severity)
                fix_version = self._extract_fix_version(rule, result)

                title = (
                    rule.get("shortDescription", {}).get("text")
                    or rule.get("name")
                    or message[:100]
                    or rule_id
                    or "Untitled finding"
                )

                description = (
                    rule.get("fullDescription", {}).get("text")
                    or rule.get("help", {}).get("text")
                    or message
                )

                fix_suggestion, fix_code = self._generate_fix(
                    rule_id=rule_id,
                    tool=tool,
                    message=message,
                    rule=rule,
                    vulnerable_line=vulnerable_line or ""
                )

                references = self._extract_references(rule)
                category = self._extract_category(
                    rule_id,
                    rule.get("properties", {}).get("tags", []) or []
                )

                package_name = None
                package_version = None
                if tool == SASTTool.TRIVY:
                    package_name = self._extract_package_name(rule, result)
                    package_version = self._extract_package_version(rule, result)

                finding = SASTFinding(
                    tool=tool,
                    severity=severity,
                    file_path=file_path,
                    line_number=line_start,
                    line_start=line_start,
                    line_end=line_end,
                    col_start=col_start,
                    col_end=col_end,
                    code_snippet=code_snippet,
                    vulnerable_line=vulnerable_line,
                    rule_id=(rule_id[:255] if rule_id else None),
                    cwe=(cwe[:255] if cwe else None),
                    cve=(cve[:100] if cve else None),
                    cvss_score=cvss,
                    title=title[:500],
                    description=description[:5000] if description else None,
                    message=message[:5000] if message else None,
                    fix_suggestion=fix_suggestion[:5000] if fix_suggestion else None,
                    fix_code=fix_code[:5000] if fix_code else None,
                    references=references,
                    category=(category[:255] if category else None),
                    package_name=(package_name[:255] if package_name else None),
                    package_version=(package_version[:100] if package_version else None),
                    fix_version=(fix_version[:100] if fix_version else None),
                    sarif_raw=result,
                )
                findings.append(finding)

        logger.info(f"{tool.value}: {len(findings)} findings")
        return findings

    def _parse_gitleaks(self, report_path: str) -> list:
        findings = []

        path = Path(report_path)
        if not path.exists() or path.stat().st_size == 0:
            logger.warning(f"Rapport Gitleaks vide ou absent: {report_path}")
            return []

        try:
            with open(report_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return []
                leaks = json.loads(content)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning(f"Gitleaks parse erreur {report_path}: {e}")
            return []

        if not isinstance(leaks, list):
            logger.warning("Format Gitleaks inattendu")
            return []

        for leak in leaks:
            rule_id = leak.get("RuleID", "")
            raw_secret = leak.get("Secret", "")
            secret_preview = self._mask_secret(raw_secret)

            severity = SASTSeverity.CRITICAL if any(
                k in rule_id.lower()
                for k in ["aws", "github", "private-key", "jwt", "token", "secret"]
            ) else SASTSeverity.HIGH

            description = (
                f"Type: {leak.get('Description', rule_id)} | "
                f"Commit: {str(leak.get('Commit', 'N/A'))[:8]} | "
                f"Secret détecté dans le code"
            )

            fix_suggestion = (
                "Révoquez ce secret immédiatement, supprimez-le du dépôt, "
                "puis remplacez-le par une variable d’environnement ou un secret manager."
            )

            fix_code = (
                "# Exemple\n"
                "import os\n"
                "API_KEY = os.environ.get('API_KEY')"
            )

            finding = SASTFinding(
                tool=SASTTool.GITLEAKS,
                severity=severity,
                file_path=leak.get("File"),
                line_number=leak.get("StartLine"),
                line_start=leak.get("StartLine"),
                line_end=leak.get("EndLine") or leak.get("StartLine"),
                rule_id=(rule_id[:255] if rule_id else None),
                cwe="CWE-312",
                cvss_score=9.5 if severity == SASTSeverity.CRITICAL else 8.1,
                title=f"Secret exposé : {rule_id}"[:500],
                description=description[:5000],
                message=(leak.get("Description") or f"Secret détecté par Gitleaks: {rule_id}")[:5000],
                fix_suggestion=fix_suggestion,
                fix_code=fix_code,
                category="Secret Exposé",
                secret_type=(rule_id[:255] if rule_id else None),
                secret_preview=(secret_preview[:255] if secret_preview else None),
                vulnerable_line=None,
                sarif_raw=leak,
            )
            findings.append(finding)

        logger.info(f"Gitleaks: {len(findings)} secrets")
        return findings

    # ============================================================
    # Helpers de parsing
    # ============================================================

    def _normalize_file_path(self, uri: str) -> Optional[str]:
        if not uri:
            return None
        if uri.startswith("file://"):
            parsed = urlparse(uri)
            return unquote(parsed.path)
        return os.path.normpath(uri)

    def _resolve_file_on_disk(self, repo_root: str, file_path: str) -> str:
        path = Path(file_path)
        if path.is_absolute():
            return str(path)
        return str((Path(repo_root) / file_path).resolve())

    def _extract_code_snippet(
        self,
        file_path: str,
        line_start: int,
        line_end: Optional[int],
        context: int = 2
    ) -> tuple[Optional[str], Optional[str]]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            if not lines or not line_start or line_start < 1:
                return None, None

            end_line = line_end or line_start
            start = max(0, line_start - 1 - context)
            end = min(len(lines), end_line + context)

            numbered_lines = []
            for i, line in enumerate(lines[start:end], start=start + 1):
                marker = ">>>" if line_start <= i <= end_line else "   "
                numbered_lines.append(f"{marker} {i:4d} | {line.rstrip()}")

            snippet = "\n".join(numbered_lines)
            vulnerable = lines[line_start - 1].rstrip() if line_start <= len(lines) else None
            return snippet, vulnerable

        except Exception as e:
            logger.debug(f"Impossible d'extraire le snippet depuis {file_path}: {e}")
            return None, None

    def _extract_vulnerable_line_from_snippet(
        self,
        snippet: str,
        line_start: Optional[int],
        line_end: Optional[int]
    ) -> Optional[str]:
        if not snippet:
            return None

        lines = snippet.splitlines()
        for line in lines:
            if line.strip():
                return line.strip()
        return None

    def _mask_secret(self, secret: str) -> str:
        if not secret:
            return "N/A"
        if len(secret) <= 8:
            return "*" * len(secret)
        return f"{secret[:4]}***{secret[-4:]}"

    def _extract_references(self, rule: dict) -> list:
        refs = []

        help_uri = rule.get("helpUri")
        if help_uri:
            refs.append(help_uri)

        properties = rule.get("properties", {})
        for key in ["references", "urls", "links"]:
            value = properties.get(key)
            if isinstance(value, list):
                refs.extend([str(v) for v in value if v])
            elif value:
                refs.append(str(value))

        return refs

    def _extract_package_name(self, rule: dict, result: dict) -> Optional[str]:
        props = rule.get("properties", {})
        for key in ["PkgName", "pkgName", "packageName", "package"]:
            if props.get(key):
                return str(props.get(key))

        message = result.get("message", {}).get("text", "")
        return message[:255] if message else None

    def _extract_package_version(self, rule: dict, result: dict) -> Optional[str]:
        props = rule.get("properties", {})
        for key in ["InstalledVersion", "installedVersion", "packageVersion", "version"]:
            if props.get(key):
                return str(props.get(key))
        return None

    def _sarif_level_to_severity(self, level: str, rule: dict) -> SASTSeverity:
        properties = rule.get("properties", {})
        tags = properties.get("tags", []) or []

        for tag in tags:
            tag_upper = str(tag).upper()
            if "CRITICAL" in tag_upper:
                return SASTSeverity.CRITICAL
            if "HIGH" in tag_upper:
                return SASTSeverity.HIGH
            if "MEDIUM" in tag_upper:
                return SASTSeverity.MEDIUM
            if "LOW" in tag_upper:
                return SASTSeverity.LOW

        security_severity = properties.get("security-severity")
        if security_severity is not None:
            try:
                score = float(security_severity)
                if score >= 9.0:
                    return SASTSeverity.CRITICAL
                if score >= 7.0:
                    return SASTSeverity.HIGH
                if score >= 4.0:
                    return SASTSeverity.MEDIUM
                return SASTSeverity.LOW
            except (TypeError, ValueError):
                pass

        mapping = {
            "error": SASTSeverity.HIGH,
            "warning": SASTSeverity.MEDIUM,
            "note": SASTSeverity.LOW,
            "none": SASTSeverity.INFO,
        }
        return mapping.get(str(level).lower(), SASTSeverity.MEDIUM)

    def _normalize_cwe(self, value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        value = str(value).strip()
        if value.startswith("CWE-"):
            return value.split(":")[0].strip()
        return value

    def _extract_cwe(self, rule: dict) -> Optional[str]:
        props = rule.get("properties", {})
        tags = props.get("tags", []) or []

        for tag in tags:
            if isinstance(tag, str) and tag.startswith("CWE-"):
                return tag

        cwe = props.get("cwe")
        if cwe:
            cwe = str(cwe)
            return cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"

        return None

    def _extract_cve(self, rule: dict, result: dict) -> Optional[str]:
        rule_id = rule.get("id", "")
        if isinstance(rule_id, str) and rule_id.startswith("CVE-"):
            return rule_id

        props = rule.get("properties", {})
        cve = props.get("cve")
        if cve:
            return str(cve)

        tags = props.get("tags", []) or []
        for tag in tags:
            if isinstance(tag, str) and tag.startswith("CVE-"):
                return tag

        return None

    def _extract_fix_version(self, rule: dict, result: dict) -> Optional[str]:
        props = rule.get("properties", {})
        for key in ["fixedVersion", "fixed_version", "fix_version"]:
            value = props.get(key)
            if value:
                return str(value)

        message = result.get("message", {}).get("text", "")
        if "Fixed Version:" in message:
            try:
                return message.split("Fixed Version:", 1)[1].strip().split()[0]
            except Exception:
                pass

        return None

    def _extract_cvss(
        self,
        rule: dict,
        result: dict,
        severity: SASTSeverity
    ) -> float:
        props = rule.get("properties", {})

        for key in ["cvss", "cvss_score", "security-severity"]:
            value = props.get(key)
            if value is not None:
                try:
                    return float(value)
                except (ValueError, TypeError):
                    pass

        estimates = {
            SASTSeverity.CRITICAL: 9.5,
            SASTSeverity.HIGH: 7.5,
            SASTSeverity.MEDIUM: 5.5,
            SASTSeverity.LOW: 3.0,
            SASTSeverity.INFO: 1.0,
        }
        return estimates.get(severity, 5.0)

    def _generate_fix(
        self,
        rule_id: str,
        tool: SASTTool,
        message: str,
        rule: dict,
        vulnerable_line: str,
    ) -> tuple[str, str]:
        fix_metadata = rule.get("properties", {}).get("fix", "")
        if fix_metadata:
            return "Correction automatique proposée par la règle.", str(fix_metadata)

        known_fixes = {
            "python.django.security.audit.raw-query": (
                "Utilisez des paramètres préparés ORM Django.",
                "# AVANT\n"
                "User.objects.raw(f\"SELECT * FROM users WHERE id={user_id}\")\n\n"
                "# APRÈS\n"
                "User.objects.raw(\"SELECT * FROM users WHERE id=%s\", [user_id])"
            ),
            "python.sqlalchemy.security.sqlalchemy-execute-raw-query": (
                "Ne concaténez jamais des variables dans une requête SQL.",
                "# AVANT\n"
                "db.execute(f\"SELECT * FROM users WHERE name='{name}'\")\n\n"
                "# APRÈS\n"
                "db.execute(text(\"SELECT * FROM users WHERE name=:name\"), {\"name\": name})"
            ),
            "javascript.react.security.audit.react-dangerouslysetinnerhtml": (
                "Évitez dangerouslySetInnerHTML et laissez React échapper le contenu.",
                "// AVANT\n"
                "<div dangerouslySetInnerHTML={{__html: userContent}} />\n\n"
                "// APRÈS\n"
                "<div>{userContent}</div>"
            ),
            "python.lang.security.audit.subprocess-shell-true": (
                "N’utilisez pas shell=True avec des entrées utilisateurs.",
                "# AVANT\n"
                "subprocess.run(f\"ls {user_dir}\", shell=True)\n\n"
                "# APRÈS\n"
                "subprocess.run([\"ls\", user_dir], shell=False)"
            ),
        }

        if rule_id in known_fixes:
            return known_fixes[rule_id]

        if tool == SASTTool.TRIVY:
            return (
                "Mettez à jour le package vers une version corrigée.",
                "# Exemple\npip install -U <package>"
            )

        if tool == SASTTool.GITLEAKS:
            return (
                "Révoquez le secret, retirez-le du dépôt et utilisez des variables d’environnement.",
                "# Exemple\nimport os\nTOKEN = os.environ.get('TOKEN')"
            )

        msg_lower = f"{message} {rule_id}".lower()

        if "sql" in msg_lower or "injection" in msg_lower:
            return (
                "Utilisez des requêtes paramétrées pour éviter l’injection SQL.",
                "# Remplacez la concaténation par des paramètres préparés."
            )

        if "xss" in msg_lower or "html" in msg_lower:
            return (
                "Échappez les sorties HTML ou utilisez le mécanisme sécurisé du framework.",
                "# Utilisez l’encodage natif du framework."
            )

        if "secret" in msg_lower or "token" in msg_lower or "password" in msg_lower:
            return (
                "Déplacez le secret hors du code source.",
                "import os\nSECRET = os.environ.get('SECRET')"
            )

        return (
            "Consultez la règle de sécurité et appliquez une correction conforme aux bonnes pratiques OWASP.",
            ""
        )

    def _extract_category(self, rule_id: str, tags: list) -> str:
        rule_lower = (rule_id or "").lower()
        if "sql" in rule_lower:
            return "Injection SQL"
        if "xss" in rule_lower:
            return "Cross-Site Scripting"
        if "path" in rule_lower:
            return "Path Traversal"
        if "secret" in rule_lower:
            return "Secret Exposé"
        if "password" in rule_lower:
            return "Credential Hardcodé"
        if "jwt" in rule_lower:
            return "Authentification"
        if "subprocess" in rule_lower:
            return "Injection Commande"
        if "ssrf" in rule_lower:
            return "SSRF"
        if "deserializ" in rule_lower:
            return "Désérialisation"

        for tag in tags:
            if "OWASP" in str(tag):
                return str(tag)

        return "Sécurité Générale"

    # ============================================================
    # Persistance + stats
    # ============================================================

    async def _save_findings(self, findings: list) -> list:
        if not findings:
            return []

        async with AsyncSessionLocal() as db:
            for finding in findings:
                db.add(finding)
            await db.commit()

            for finding in findings:
                try:
                    await db.refresh(finding)
                except Exception as e:
                    logger.warning(f"Impossible de refresh finding: {e}")

        return findings

    def _compute_stats(self, findings: list) -> dict:
        by_tool = {}
        by_severity = {}

        for finding in findings:
            tool = finding.tool.value if finding.tool else "unknown"
            severity = finding.severity.value if finding.severity else "UNKNOWN"

            by_tool[tool] = by_tool.get(tool, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1

        return {
            "total": len(findings),
            "by_tool": by_tool,
            "by_severity": by_severity,
            "has_critical": by_severity.get("CRITICAL", 0) > 0,
            "has_secrets": by_tool.get("gitleaks", 0) > 0,
        }