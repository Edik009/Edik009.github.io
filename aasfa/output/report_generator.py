"""
Report generator for saving scan results
"""
import json
from pathlib import Path
from typing import Optional
from ..core.result_aggregator import ResultAggregator


class ReportGenerator:
    """Генератор отчетов"""
    
    @staticmethod
    def generate_text_report(aggregator: ResultAggregator, output_file: str):
        """Генерация текстового отчета"""
        from .formatter import ASSESSMENT_ONLY_DISCLAIMER
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("="*70 + "\n")
            f.write("AASFA Scanner Report\n")
            f.write("="*70 + "\n")
            f.write(f"{ASSESSMENT_ONLY_DISCLAIMER}\n\n")
            
            summary = aggregator.get_summary()
            f.write(f"Scan Date: {summary['start_time']}\n")
            f.write(f"Duration: {summary['duration_seconds']:.2f} seconds\n")
            f.write(f"Total Checks: {summary['total_checks']}\n")
            f.write(f"Vulnerabilities Found: {summary['vulnerabilities_found']}\n\n")
            
            severity_counts = summary['severity_breakdown']
            f.write("Severity Breakdown:\n")
            f.write(f"  CRITICAL: {severity_counts.get('CRITICAL', 0)}\n")
            f.write(f"  HIGH: {severity_counts.get('HIGH', 0)}\n")
            f.write(f"  MEDIUM: {severity_counts.get('MEDIUM', 0)}\n")
            f.write(f"  LOW: {severity_counts.get('LOW', 0)}\n\n")
            
            if summary['device_info']:
                f.write("Device Information:\n")
                for key, value in summary['device_info'].items():
                    f.write(f"  {key}: {value}\n")
                f.write("\n")
            
            vulnerabilities = aggregator.get_vulnerabilities()
            if vulnerabilities:
                f.write("="*70 + "\n")
                f.write("VULNERABILITIES\n")
                f.write("="*70 + "\n\n")
                
                for vuln in vulnerabilities:
                    f.write(f"[{vuln.severity}] VECTOR_{vuln.vector_id:03d}: {vuln.vector_name}\n")
                    f.write(f"Details: {vuln.details}\n")
                    f.write(f"Timestamp: {vuln.timestamp}\n\n")
    
    @staticmethod
    def generate_json_report(aggregator: ResultAggregator, output_file: str):
        """Генерация JSON отчета"""
        data = aggregator.to_dict()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    @staticmethod
    def save_report(aggregator: ResultAggregator, output_file: Optional[str]):
        """Сохранение отчета в файл"""
        if not output_file:
            return
        
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if output_file.endswith('.json'):
            ReportGenerator.generate_json_report(aggregator, output_file)
        else:
            ReportGenerator.generate_text_report(aggregator, output_file)
