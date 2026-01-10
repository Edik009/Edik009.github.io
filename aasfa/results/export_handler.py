"""Export handlers for different formats"""

import json
import csv
from pathlib import Path
from typing import Dict, Any

from ..core.result_aggregator import ResultAggregator
from ..cli.colors import green, red


class ExportHandler:
    """Handle export of scan results to various formats"""

    def export(self, aggregator: ResultAggregator, filename: str, format: str) -> bool:
        """Export results to specified format"""
        try:
            # Ensure results directory exists
            Path(filename).parent.mkdir(parents=True, exist_ok=True)

            exporters = {
                "json": self._export_json,
                "txt": self._export_txt,
                "csv": self._export_csv,
                "html": self._export_html,
                "pdf": self._export_pdf
            }

            exporter = exporters.get(format, self._export_txt)
            return exporter(aggregator, filename)

        except Exception as e:
            print(f"Error: {e}")
            return False

    def _export_json(self, aggregator: ResultAggregator, filename: str) -> bool:
        """Export to JSON format"""
        data = {
            "summary": aggregator.get_summary(),
            "vulnerabilities": [
                {
                    "id": v.vector_id,
                    "name": v.vector_name,
                    "severity": v.severity,
                    "details": v.details if isinstance(v, object) else str(v.details),
                    "confidence": getattr(v, 'confidence', 100) if isinstance(v, object) else 100
                }
                for v in aggregator.get_vulnerabilities()
            ],
            "severity_counts": aggregator.get_severity_counts(),
            "risk_score": aggregator.get_risk_score()
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return True

    def _export_txt(self, aggregator: ResultAggregator, filename: str) -> bool:
        """Export to plain text format"""
        vulnerabilities = aggregator.get_vulnerabilities()

        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("СКАНИРОВАНИЕ БЕЗОПАСНОСТИ - ОТЧЁТ\n")
            f.write("=" * 70 + "\n\n")

            summary = aggregator.get_summary()
            f.write(f"Target: {summary.get('target', 'Unknown')}\n")
            f.write(f"Scan Duration: {summary['duration_seconds']:.2f} seconds\n")
            f.write(f"Total Checks: {summary['total_checks']}\n")
            f.write(f"Vulnerabilities Found: {summary['vulnerabilities_found']}\n\n")

            f.write("=" * 70 + "\n")
            f.write("НАЙДЕННЫЕ УЯЗВИМОСТИ\n")
            f.write("=" * 70 + "\n\n")

            for vuln in vulnerabilities:
                severity = vuln.severity if hasattr(vuln, 'severity') else 'INFO'
                vector_id = vuln.vector_id if hasattr(vuln, 'vector_id') else 0
                vector_name = vuln.vector_name if hasattr(vuln, 'vector_name') else 'Unknown'
                details = vuln.details if hasattr(vuln, 'details') else ''

                f.write(f"[{severity}] VECTOR_{vector_id}: {vector_name}\n")
                f.write(f"    {details}\n\n")

            f.write("=" * 70 + "\n")
            f.write(f"Risk Score: {aggregator.get_risk_score()}/100\n")
            f.write("=" * 70 + "\n")

        return True

    def _export_csv(self, aggregator: ResultAggregator, filename: str) -> bool:
        """Export to CSV format"""
        vulnerabilities = aggregator.get_vulnerabilities()

        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Vector ID', 'Name', 'Severity', 'Details', 'Confidence'])

            for vuln in vulnerabilities:
                severity = vuln.severity if hasattr(vuln, 'severity') else 'INFO'
                vector_id = vuln.vector_id if hasattr(vuln, 'vector_id') else 0
                vector_name = vuln.vector_name if hasattr(vuln, 'vector_name') else 'Unknown'
                details = vuln.details if hasattr(vuln, 'details') else ''
                confidence = getattr(vuln, 'confidence', 100) if hasattr(vuln, 'confidence') else 100

                writer.writerow([vector_id, vector_name, severity, details, confidence])

        return True

    def _export_html(self, aggregator: ResultAggregator, filename: str) -> bool:
        """Export to HTML format"""
        vulnerabilities = aggregator.get_vulnerabilities()
        summary = aggregator.get_summary()

        html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Отчёт сканирования безопасности</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #4CAF50; color: white; padding: 20px; text-align: center; }}
        .summary {{ background: #f5f5f5; padding: 15px; margin: 20px 0; }}
        .vulnerability {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; }}
        .critical {{ border-left: 5px solid #f44336; }}
        .high {{ border-left: 5px solid #ff9800; }}
        .medium {{ border-left: 5px solid #ffeb3b; }}
        .low {{ border-left: 5px solid #4caf50; }}
        .severity {{ font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Отчёт сканирования безопасности</h1>
        <p>{summary.get('target', 'Unknown')}</p>
    </div>

    <div class="summary">
        <h2>Краткая статистика</h2>
        <p>Время сканирования: {summary['duration_seconds']:.2f} секунд</p>
        <p>Проверено векторов: {summary['total_checks']}</p>
        <p>Найдено уязвимостей: {summary['vulnerabilities_found']}</p>
        <p>Risk Score: {aggregator.get_risk_score()}/100</p>
    </div>

    <h2>Найденные уязвимости</h2>
"""

        for vuln in vulnerabilities:
            severity = vuln.severity if hasattr(vuln, 'severity') else 'INFO'
            vector_id = vuln.vector_id if hasattr(vuln, 'vector_id') else 0
            vector_name = vuln.vector_name if hasattr(vuln, 'vector_name') else 'Unknown'
            details = vuln.details if hasattr(vuln, 'details') else ''

            html += f"""
    <div class="vulnerability {severity.lower()}">
        <p class="severity">[{severity}] VECTOR_{vector_id}: {vector_name}</p>
        <p>{details}</p>
    </div>
"""

        html += """
</body>
</html>
"""

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)

        return True

    def _export_pdf(self, aggregator: ResultAggregator, filename: str) -> bool:
        """Export to PDF format (requires reportlab)"""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib import colors

            doc = SimpleDocTemplate(filename, pagesize=letter)
            story = []
            styles = getSampleStyleSheet()

            # Title
            story.append(Paragraph("Отчёт сканирования безопасности", styles['Title']))
            story.append(Spacer(1, 0.2 * inch))

            # Summary
            summary = aggregator.get_summary()
            summary_data = [
                ["Target:", summary.get('target', 'Unknown')],
                ["Duration:", f"{summary['duration_seconds']:.2f} seconds"],
                ["Total Checks:", str(summary['total_checks'])],
                ["Vulnerabilities:", str(summary['vulnerabilities_found'])],
                ["Risk Score:", f"{aggregator.get_risk_score()}/100"]
            ]

            summary_table = Table(summary_data, colWidths=[1.5*inch, 4*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            story.append(summary_table)
            story.append(Spacer(1, 0.2 * inch))

            # Vulnerabilities
            story.append(Paragraph("Найденные уязвимости", styles['Heading2']))

            vulnerabilities = aggregator.get_vulnerabilities()
            for vuln in vulnerabilities:
                severity = vuln.severity if hasattr(vuln, 'severity') else 'INFO'
                vector_id = vuln.vector_id if hasattr(vuln, 'vector_id') else 0
                vector_name = vuln.vector_name if hasattr(vuln, 'vector_name') else 'Unknown'
                details = vuln.details if hasattr(vuln, 'details') else ''

                story.append(Paragraph(f"[{severity}] VECTOR_{vector_id}: {vector_name}", styles['Heading3']))
                story.append(Paragraph(str(details), styles['Normal']))
                story.append(Spacer(1, 0.1 * inch))

            doc.build(story)
            return True

        except ImportError:
            # reportlab not installed, fall back to HTML
            print(f"Warning: reportlab not installed, exporting as HTML instead")
            new_filename = filename.rreplace('.pdf', '.html', 1)
            return self._export_html(aggregator, new_filename)
        except Exception as e:
            print(f"Error exporting PDF: {e}")
            return False
