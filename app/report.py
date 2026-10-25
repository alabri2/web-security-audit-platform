import re
from pathlib import Path
from html import escape

from app.config import OUTPUT_DIR
from app.database import get_scan, get_findings
from app.scoring import get_security_level

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        KeepTogether,
    )
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def clean_text(text: str) -> str:
    if not text:
        return ""
    text = str(text)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = re.sub(r"\[[0-9;]*m", "", text)
    text = text.replace("\r", "")
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _score_color(score: int) -> str:
    if score >= 75:
        return "#6b8f71"
    if score >= 50:
        return "#d19a66"
    return "#b85c38"


def _severity_counts(findings):
    counts = {k: 0 for k in SEVERITY_ORDER}
    for item in findings:
        sev = str(item.get("severity", "info")).lower()
        counts[sev if sev in counts else "info"] += 1
    return counts


def _recommendation(title: str, tool: str) -> str:
    t = (title or "").lower()
    tool = (tool or "").lower()

    if "x-frame-options" in t:
        return "Ajouter l’en-tête X-Frame-Options ou utiliser la directive CSP frame-ancestors pour limiter le risque de clickjacking."
    if "x-content-type-options" in t:
        return "Ajouter l’en-tête X-Content-Type-Options avec la valeur nosniff."
    if "strict-transport-security" in t:
        return "Activer l’en-tête Strict-Transport-Security afin d’imposer l’utilisation de HTTPS."
    if "referrer-policy" in t:
        return "Ajouter une politique Referrer-Policy adaptée afin de limiter la fuite d’informations."
    if "content-security-policy" in t:
        return "Définir une politique Content-Security-Policy adaptée afin de mieux contrôler les ressources chargées par le navigateur."
    if "ssl" in t or "tls" in t or tool == "sslscan":
        return "Revoir la configuration TLS/SSL et désactiver les protocoles ou suites cryptographiques faibles ou inutiles."
    if "port" in t or tool == "nmap":
        return "Vérifier les services exposés et fermer ou restreindre les ports qui ne sont pas nécessaires."
    if "technology" in t or tool == "whatweb":
        return "Réduire l’exposition inutile des technologies dans les réponses HTTP et les en-têtes."
    if "wordpress" in t or tool == "wpscan":
        return "Mettre à jour WordPress, les extensions et les thèmes, puis limiter l’exposition des versions."
    if "sql" in t or tool == "sqlmap":
        return "Renforcer la validation des entrées côté serveur et utiliser des requêtes paramétrées."
    if "xss" in t or tool == "dalfox":
        return "Renforcer l’échappement des sorties et la validation des entrées pour réduire les risques XSS."
    if "header" in t or tool == "headers":
        return "Compléter la configuration des en-têtes de sécurité HTTP manquants."
    if "timeout" in t:
        return "Relancer le test avec un délai adapté et vérifier la disponibilité réelle du service."
    return "Analyser ce résultat plus en détail et appliquer la mesure de correction appropriée."


def _impact_text(severity: str) -> str:
    sev = str(severity or "info").lower()
    if sev == "critical":
        return "Cette anomalie peut entraîner une compromission importante du système ou une exploitation immédiate."
    if sev == "high":
        return "Cette anomalie peut avoir un impact significatif sur la sécurité de la cible."
    if sev == "medium":
        return "Cette anomalie augmente la surface d’attaque et doit être corrigée dans le plan de remédiation."
    if sev == "low":
        return "Cette anomalie a un impact limité mais doit être corrigée dans le cadre du durcissement de sécurité."
    return "Ce résultat est informatif et aide à mieux comprendre l’exposition technique de la cible."


def _description_text(title: str, description: str, tool: str) -> str:
    t = (title or "").lower()
    d = clean_text(description or "")
    tool = (tool or "").lower()

    if "x-frame-options" in t:
        return "L’en-tête de sécurité X-Frame-Options est absent. La page pourrait donc être intégrée dans une iframe externe."
    if "x-content-type-options" in t:
        return "L’en-tête X-Content-Type-Options n’est pas présent. Certains contenus peuvent alors être interprétés de manière non souhaitée par le navigateur."
    if "strict-transport-security" in t:
        return "L’en-tête Strict-Transport-Security est absent. Le navigateur n’est donc pas forcé à utiliser HTTPS lors des visites suivantes."
    if "referrer-policy" in t:
        return "L’en-tête Referrer-Policy est absent. Des informations sur l’origine de navigation peuvent être transmises inutilement."
    if "content-security-policy" in t:
        return "Aucune politique Content-Security-Policy n’a été détectée. Le contrôle des ressources côté navigateur reste donc limité."
    if "timeout" in t and tool == "nmap":
        return "Le scan Nmap n’a pas pu se terminer dans le délai prévu. Le résultat reste incomplet et doit être interprété avec prudence."
    if "timeout" in t and tool == "nikto":
        return "Le scan Nikto a dépassé le temps imparti. L’analyse automatique n’a donc pas pu aller jusqu’à son terme."
    if "technology" in t or tool == "whatweb":
        return "Plusieurs technologies et composants applicatifs ont été identifiés publiquement. Cette visibilité facilite le profilage technique de la cible."
    if "wordpress" in t or tool == "wpscan":
        return "Des éléments liés à WordPress ont été détectés sur la cible. Une vérification des versions et composants exposés est recommandée."
    if "api" in t:
        return "Des indices laissent penser que la cible expose une API ou une documentation associée. Une vérification complémentaire des points d’entrée est conseillée."

    if d:
        return d

    return "Une anomalie ou une information technique a été détectée lors de l’analyse automatique."


def _normalize_finding(item):
    return {
        "severity": str(item.get("severity", "info")).lower(),
        "title": clean_text(item.get("title", "Finding")) or "Finding",
        "tool": clean_text(item.get("tool", "")),
        "description": _description_text(
            item.get("title", ""),
            item.get("description", ""),
            item.get("tool", "")
        ),
        "evidence": clean_text(item.get("evidence", "")),
    }


def _filter_findings(findings):
    cleaned = [_normalize_finding(x) for x in findings]

    filtered = []
    for f in cleaned:
        title_low = f["title"].lower()

        if f["severity"] == "info" and (
            "type de cible détecté automatiquement" in title_low
            or "type de cible choisi manuellement" in title_low
            or "automatic target type detection" in title_low
            or "manual target type selection" in title_low
        ):
            continue

        filtered.append(f)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    filtered.sort(key=lambda x: order.get(x["severity"], 5))
    return filtered


def _top_findings(findings, limit=5):
    return findings[:limit]


def _severity_label(sev: str) -> str:
    sev = str(sev or "info").lower()
    labels = {
        "critical": "Critique",
        "high": "Élevée",
        "medium": "Moyenne",
        "low": "Faible",
        "info": "Info",
    }
    return labels.get(sev, "Info")


def _executive_summary(score: int, level: str, counts: dict) -> str:
    if counts["critical"] > 0 or counts["high"] > 0:
        return (
            f"Le scan met en évidence un niveau de sécurité global de <b>{score}%</b> "
            f"(niveau <b>{escape(level)}</b>), mais des vulnérabilités importantes ont été identifiées. "
            f"Des actions correctives prioritaires sont recommandées afin de réduire le risque d’exploitation."
        )

    if counts["medium"] > 0:
        return (
            f"Le scan présente un score global de <b>{score}%</b> "
            f"(niveau <b>{escape(level)}</b>). Aucune vulnérabilité critique n’a été relevée, "
            f"mais certaines faiblesses de sévérité moyenne nécessitent une correction dans le plan de remédiation."
        )

    if counts["low"] > 0:
        return (
            f"Le scan présente un score global de <b>{score}%</b> "
            f"(niveau <b>{escape(level)}</b>). Aucune vulnérabilité critique ou élevée n’a été détectée. "
            f"Les constats relevés concernent principalement le durcissement de la configuration de sécurité."
        )

    return (
        f"Le scan présente un score global de <b>{score}%</b> "
        f"(niveau <b>{escape(level)}</b>) et n’a pas mis en évidence de faiblesse significative. "
        f"La posture de sécurité observée apparaît satisfaisante au regard des vérifications effectuées."
    )


def _general_conclusion(score: int, level: str, counts: dict) -> str:
    if counts["critical"] > 0 or counts["high"] > 0:
        return (
            f"La cible auditée présente plusieurs vulnérabilités nécessitant une remédiation prioritaire. "
            f"Le niveau global observé ({score}% – {level}) doit être amélioré avant toute mise en production ou exposition prolongée."
        )

    if counts["medium"] > 0:
        return (
            f"La cible auditée présente un niveau de sécurité global correct ({score}% – {level}), "
            f"mais des améliorations restent nécessaires pour réduire durablement la surface d’attaque."
        )

    return (
        f"La cible auditée présente un niveau de sécurité global satisfaisant ({score}% – {level}). "
        f"Les améliorations recommandées relèvent principalement du durcissement, de la réduction de la surface d’exposition "
        f"et de la validation après correction."
    )


def _prioritized_recommendations(findings):
    titles = " ".join((f.get("title", "") + " " + f.get("tool", "")) for f in findings).lower()
    recs = []

    if "x-frame-options" in titles or "x-content-type-options" in titles or "content-security-policy" in titles:
        recs.append("Priorité 1 : compléter les en-têtes de sécurité HTTP manquants.")
    if "ssl" in titles or "tls" in titles or "sslscan" in titles:
        recs.append("Priorité 2 : renforcer la configuration TLS/SSL et supprimer les protocoles ou options faibles.")
    if "port" in titles or "nmap" in titles:
        recs.append("Priorité 3 : réduire l’exposition des services réseau strictement au nécessaire.")
    if "technology" in titles or "whatweb" in titles or "wordpress" in titles:
        recs.append("Priorité 4 : limiter la divulgation d’informations techniques sur la cible.")
    recs.append("Priorité 5 : relancer un scan de validation après correction afin de confirmer l’amélioration.")

    return recs


def build_html_report(scan_id: str) -> Path:
    scan = get_scan(scan_id)
    raw_findings = get_findings(scan_id)
    findings = _filter_findings(raw_findings)

    out_dir = OUTPUT_DIR / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)
    report = out_dir / "report.html"

    score = int(scan.get("score") or 0)
    level = get_security_level(score)
    color = _score_color(score)
    counts = _severity_counts(findings)
    top_findings = _top_findings(findings, 5)

    exec_summary = _executive_summary(score, level, counts)
    conclusion = _general_conclusion(score, level, counts)
    prioritized_recs = _prioritized_recommendations(findings)

    findings_html = []
    for x in findings:
        sev = str(x["severity"]).lower()
        cls = f"sev-{sev}" if sev in {"critical", "high", "medium", "low", "info"} else "sev-info"

        recommendation = _recommendation(x["title"], x["tool"])
        impact = _impact_text(x["severity"])
        severity_label = _severity_label(x["severity"])
        evidence = x.get("evidence", "")

        evidence_html = (
            f"<p><strong>Preuve :</strong><br><code>{escape(evidence[:1200])}</code></p>"
            if evidence else ""
        )

        findings_html.append(
            f"""
            <div class='finding {cls}'>
                <div class='finding-head'>
                    <div>
                        <strong>{escape(x['title'])}</strong>
                        <div class='meta'>Outil : {escape(x['tool'])} · Sévérité : {escape(severity_label)}</div>
                    </div>
                    <span class='badge {cls}'>{escape(severity_label)}</span>
                </div>
                <p><strong>Description :</strong> {escape(x['description'])}</p>
                {evidence_html}
                <p><strong>Impact :</strong> {escape(impact)}</p>
                <p><strong>Recommandation :</strong> {escape(recommendation)}</p>
            </div>
            """
        )

    key_risks_html = "".join(
        f"<li><strong>{escape(x['title'])}</strong> — {escape(_severity_label(x['severity']))} ({escape(x['tool'])})</li>"
        for x in top_findings
    )

    summary_rows = "".join(
        f"<div class='metric'><span>{label}</span><strong>{counts[key]}</strong></div>"
        for key, label in [
            ("critical", "Critique"),
            ("high", "Élevée"),
            ("medium", "Moyenne"),
            ("low", "Faible"),
            ("info", "Info"),
        ]
    )

    html = f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Rapport d'audit - {escape(scan_id)}</title>
<style>
body{{font-family:Arial,sans-serif;background:#f7f3eb;color:#3f3426;margin:0;padding:0}}
.wrapper{{max-width:1150px;margin:0 auto;padding:30px}}
.card{{background:#fffdf8;border:1px solid #eadfce;border-radius:18px;padding:24px;margin-bottom:20px;box-shadow:0 10px 24px rgba(91,74,54,.06)}}
.hero{{background:linear-gradient(135deg,#6f5a44,#8a735c);color:#fff}}
h1,h2,h3{{margin-top:0}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}}
.metric{{background:#faf5ec;border:1px solid #eadfce;border-radius:12px;padding:14px;display:flex;justify-content:space-between;align-items:center}}
.score-wrapper{{display:flex;justify-content:center;margin:24px 0}}
.score-circle{{--size:190px;--thickness:16px;width:var(--size);height:var(--size);border-radius:50%;background:conic-gradient({color} calc({score} * 1%), #ddd4c6 0);display:flex;align-items:center;justify-content:center;position:relative}}
.score-circle::before{{content:"";position:absolute;width:calc(var(--size) - 2 * var(--thickness));height:calc(var(--size) - 2 * var(--thickness));background:#fffdf8;border-radius:50%}}
.score-inner{{position:relative;z-index:1;display:flex;flex-direction:column;align-items:center}}
.score-inner span{{font-size:38px;font-weight:700}}
.score-inner small{{margin-top:6px;color:#7b6d5c}}
.finding{{background:#faf8f2;padding:18px;border-radius:12px;margin-bottom:16px;border-left:5px solid #d8cdbb}}
.finding-head{{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}}
.meta{{font-size:13px;color:#7b6d5c;margin-top:6px}}
.badge{{padding:6px 10px;border-radius:999px;font-size:12px;font-weight:700}}
.sev-critical{{border-left-color:#8f2d2d}} .badge.sev-critical{{background:#fbe3e3;color:#8f2d2d}}
.sev-high{{border-left-color:#c65d3a}} .badge.sev-high{{background:#f9e5dd;color:#9a3f21}}
.sev-medium{{border-left-color:#d19a66}} .badge.sev-medium{{background:#f8eedf;color:#9a6a2f}}
.sev-low{{border-left-color:#7b9e78}} .badge.sev-low{{background:#e9f1e7;color:#557252}}
.sev-info{{border-left-color:#8a735c}} .badge.sev-info{{background:#efe8de;color:#6f5a44}}
.footer{{color:#7b6d5c;font-size:13px;text-align:center;padding-bottom:30px}}
ul{{line-height:1.8}}
code{{display:block;white-space:pre-wrap;background:#f4efe7;border:1px solid #e3d8c7;padding:10px;border-radius:8px;margin-top:6px;font-size:12px}}
</style>
</head>
<body>
<div class="wrapper">
  <section class="card hero">
    <h1>Rapport d’audit de sécurité</h1>
    <p>Rapport généré automatiquement après vérification de l’autorisation et classification de la cible.</p>
  </section>

  <section class="card">
    <h2>Résumé exécutif</h2>
    <div class="grid">
      <div class="metric"><span>Cible</span><strong>{escape(scan.get("target",""))}</strong></div>
      <div class="metric"><span>Mode de scan</span><strong>{escape(scan.get("mode",""))}</strong></div>
      <div class="metric"><span>Sélection du type</span><strong>{escape(scan.get("selection_mode","auto"))}</strong></div>
      <div class="metric"><span>Type final</span><strong>{escape(scan.get("target_type","unknown"))}</strong></div>
      <div class="metric"><span>Autorisation</span><strong>{"Oui" if scan.get("authorization_confirmed") else "Non"}</strong></div>
      <div class="metric"><span>Statut</span><strong>{escape(scan.get("status",""))}</strong></div>
      <div class="metric"><span>Début</span><strong>{escape(str(scan.get("start_time","")))}</strong></div>
      <div class="metric"><span>Fin</span><strong>{escape(str(scan.get("end_time","")))}</strong></div>
    </div>

    <div class="score-wrapper">
      <div class="score-circle">
        <div class="score-inner">
          <span>{score}%</span>
          <small>{escape(level)}</small>
        </div>
      </div>
    </div>

    <p>{exec_summary}</p>
    <div class="grid">{summary_rows}</div>
  </section>

  <section class="card">
    <h2>Points principaux</h2>
    {("<ul>" + key_risks_html + "</ul>") if key_risks_html else "<p>Aucun risque significatif n’a été mis en évidence.</p>"}
  </section>

  <section class="card">
    <h2>Périmètre et méthodologie</h2>
    <p>
      Le présent audit automatique a été réalisé sur la cible indiquée dans le résumé exécutif.
      Il comprend une phase de fingerprinting initial, suivie de l’exécution d’outils adaptés
      au type de cible détecté ou sélectionné manuellement.
    </p>
    <p>
      Les résultats fournis par ce rapport doivent être interprétés comme une aide à la détection
      et au durcissement de sécurité. Ils ne remplacent pas une analyse manuelle complète.
    </p>
    <p>
      Mode de sélection du type : <strong>{escape(scan.get("selection_mode","auto"))}</strong>
      {f" · Type demandé : <strong>{escape(scan.get('requested_target_type') or '')}</strong>" if scan.get("requested_target_type") else ""}
    </p>
  </section>

  <section class="card">
    <h2>Constats détaillés</h2>
    {''.join(findings_html) if findings_html else "<p>Aucun constat technique significatif n’a été remonté.</p>"}
  </section>

  <section class="card">
    <h2>Recommandations générales</h2>
    <ul>
      {''.join(f"<li>{escape(r)}</li>" for r in prioritized_recs)}
    </ul>
  </section>

  <section class="card">
    <h2>Conclusion</h2>
    <p>{conclusion}</p>
  </section>
</div>
<div class="footer">WebScanner · Rapport d’audit automatique</div>
</body>
</html>"""

    report.write_text(html, encoding="utf-8")
    return report


def build_pdf_report(scan_id: str) -> Path:
    out_dir = OUTPUT_DIR / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = out_dir / "report.pdf"

    if not REPORTLAB_AVAILABLE:
        pdf_path.write_text("Install reportlab to generate the PDF report.", encoding="utf-8")
        return pdf_path

    scan = get_scan(scan_id)
    raw_findings = get_findings(scan_id)
    findings = _filter_findings(raw_findings)

    counts = _severity_counts(findings)
    score = int(scan.get("score") or 0)
    level = get_security_level(score)

    exec_summary = _executive_summary(score, level, counts)
    conclusion = _general_conclusion(score, level, counts)
    prioritized_recs = _prioritized_recommendations(findings)

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="SectionTitle",
        parent=styles["Heading2"],
        spaceAfter=8,
        textColor=colors.HexColor("#6f5a44")
    ))
    styles.add(ParagraphStyle(
        name="BodySmall",
        parent=styles["BodyText"],
        fontSize=9,
        leading=12
    ))
    styles.add(ParagraphStyle(
        name="CodeSmall",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#4a4033")
    ))

    story = []

    story.append(Paragraph("Rapport d’audit de sécurité", styles["Title"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Rapport automatisé généré par WebScanner.", styles["BodyText"]))
    story.append(Spacer(1, 10))

    summary_data = [
        ["Cible", scan.get("target", "")],
        ["Mode de scan", scan.get("mode", "")],
        ["Sélection du type", scan.get("selection_mode", "auto")],
        ["Type final", scan.get("target_type", "unknown")],
        ["Autorisation", "Oui" if scan.get("authorization_confirmed") else "Non"],
        ["Statut", scan.get("status", "")],
        ["Début", str(scan.get("start_time", ""))],
        ["Fin", str(scan.get("end_time", ""))],
        ["Score", f"{score}% ({level})"],
    ]

    tbl = Table(summary_data, colWidths=[55 * mm, 110 * mm])
    tbl.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d8cdbb")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Résumé exécutif", styles["SectionTitle"]))
    story.append(Paragraph(exec_summary, styles["BodyText"]))
    story.append(Spacer(1, 8))

    sev_table = Table(
        [
            ["Niveau", "Nombre"],
            ["Critique", str(counts["critical"])],
            ["Élevée", str(counts["high"])],
            ["Moyenne", str(counts["medium"])],
            ["Faible", str(counts["low"])],
            ["Info", str(counts["info"])],
        ],
        colWidths=[60 * mm, 30 * mm]
    )
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3ede3")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d8cdbb")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Périmètre et méthodologie", styles["SectionTitle"]))
    story.append(Paragraph(
        "L’audit automatique comprend une phase de fingerprinting, suivie de contrôles adaptés "
        "au type de cible détecté ou sélectionné manuellement. Les résultats doivent être interprétés "
        "comme une aide au diagnostic et au durcissement, et non comme un audit manuel exhaustif.",
        styles["BodyText"]
    ))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Constats détaillés", styles["SectionTitle"]))
    if findings:
        for idx, item in enumerate(findings, start=1):
            sev_label = _severity_label(item.get("severity", "info"))
            title = item.get("title", "Finding")
            tool = item.get("tool", "")
            desc = item.get("description", "")
            evidence = item.get("evidence", "")
            recommendation = _recommendation(title, tool)
            impact = _impact_text(item.get("severity", "info"))

            block = []
            block.append(Paragraph(f"{idx}. {escape(title)} [{escape(sev_label)}] - {escape(tool)}", styles["Heading4"]))
            block.append(Paragraph(f"<b>Description :</b> {escape(desc)}", styles["BodyText"]))

            if evidence:
                block.append(Paragraph(f"<b>Preuve :</b> {escape(evidence[:1000])}", styles["CodeSmall"]))

            block.append(Paragraph(f"<b>Impact :</b> {escape(impact)}", styles["BodySmall"]))
            block.append(Paragraph(f"<b>Recommandation :</b> {escape(recommendation)}", styles["BodySmall"]))
            block.append(Spacer(1, 8))
            story.append(KeepTogether(block))
    else:
        story.append(Paragraph("Aucune anomalie majeure n’a été remontée par les outils.", styles["BodyText"]))

    story.append(Spacer(1, 8))
    story.append(Paragraph("Recommandations générales", styles["SectionTitle"]))
    for line in prioritized_recs:
        story.append(Paragraph(f"• {escape(line)}", styles["BodyText"]))

    story.append(Spacer(1, 8))
    story.append(Paragraph("Conclusion", styles["SectionTitle"]))
    story.append(Paragraph(conclusion, styles["BodyText"]))

    doc.build(story)
    return pdf_path
