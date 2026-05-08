import os
import ast
import docx
from docx.shared import Pt, Inches

def extract_code_info(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            code = f.read()
    except:
        return []

    try:
        tree = ast.parse(code)
    except Exception as e:
        return []

    details = []
    
    # Get module docstring
    module_doc = ast.get_docstring(tree)
    if module_doc:
        details.append(("Module Docstring", module_doc))

    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            class_name = node.name
            class_doc = ast.get_docstring(node)
            details.append((f"Class: {class_name}", class_doc or "No docstring provided."))
            
            for child in node.body:
                if isinstance(child, ast.FunctionDef):
                    func_name = child.name
                    args = [arg.arg for arg in child.args.args]
                    func_doc = ast.get_docstring(child)
                    details.append((f"  Method: {func_name}({', '.join(args)})", func_doc or "No docstring provided."))
                    
        elif isinstance(node, ast.FunctionDef):
            func_name = node.name
            args = [arg.arg for arg in node.args.args]
            func_doc = ast.get_docstring(node)
            details.append((f"Function: {func_name}({', '.join(args)})", func_doc or "No docstring provided."))
            
    return details

def create_massive_doc():
    doc = docx.Document()
    
    style = doc.styles['Normal']
    font = style.font
    font.name = 'Arial'
    font.size = Pt(11)

    doc.add_heading('Rule-Based SOAR - Comprehensive Technical Manual', 0)
    
    doc.add_heading('1. Executive Summary', level=1)
    doc.add_paragraph(
        "This manual provides an exhaustive, granular breakdown of the Rule-Based Security Orchestration, "
        "Automation, and Response (SOAR) framework. It covers every component, class, method, and configuration "
        "file within the architecture to serve as a complete reference guide for developers, SOC analysts, and system administrators."
    )
    doc.add_paragraph(
        "The system strictly follows a rule-based detection approach, utilizing predefined logic to correlate security events, "
        "map them to compliance frameworks (MITRE, NIST, OWASP), and automatically execute mitigation playbooks."
    )

    directories = [
        ('actions', 'Action Execution & Tracking'),
        ('adapters', 'External Adapters (Docker, etc.)'),
        ('api', 'REST API & WebSockets'),
        ('collector', 'Event Ingestion (Elasticsearch, IoT)'),
        ('config', 'System Configurations & Rules'),
        ('correlator', 'Event Correlation & Thresholding'),
        ('enrichment', 'Threat Intelligence Enrichment'),
        ('mappings', 'Framework Compliance'),
        ('normalizer', 'Log Standardization'),
        ('playbooks', 'Playbook Execution Engine'),
        ('playbook_scripts', 'Mitigation Scripts (Endpoint, Network, IoT)'),
        ('rules', 'Detection Rules Base'),
        ('simulator', 'Attack Simulation Framework'),
        ('utils', 'Core Utilities'),
        ('.', 'Root Execution Files')
    ]

    chapter_num = 2
    for directory, desc in directories:
        doc.add_heading(f'{chapter_num}. {directory.capitalize()} Module: {desc}', level=1)
        doc.add_paragraph(f"This section details the internal mechanics, classes, and methods of the {directory} component.")
        
        dir_path = directory if directory != '.' else '.'
        if not os.path.exists(dir_path):
            continue
            
        files_found = False
        
        for root, dirs, files in os.walk(dir_path):
            if '__pycache__' in root or 'node_modules' in root or '.git' in root or '.venv' in root:
                continue
                
            for file in files:
                if not file.endswith('.py') and not file.endswith('.yaml') and not file.endswith('.json'):
                    continue
                    
                if file == 'generate_docx.py':
                    continue
                    
                files_found = True
                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, '.')
                
                doc.add_heading(f'File: {rel_path}', level=2)
                
                if file.endswith('.py'):
                    info = extract_code_info(filepath)
                    if not info:
                        doc.add_paragraph("Standard Python module with procedural execution or imports.")
                    else:
                        for title, details in info:
                            p = doc.add_paragraph()
                            p.add_run(title).bold = True
                            p.add_run(f"\n{details}")
                            
                elif file.endswith('.yaml') or file.endswith('.json'):
                    doc.add_paragraph("Configuration / Mapping File.")
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            content = f.read()
                            # Print first 50 lines to avoid insane bloat, but still give deep detail
                            lines = content.split('\n')
                            preview = '\n'.join(lines[:100])
                            if len(lines) > 100:
                                preview += "\n... [Truncated for brevity]"
                            doc.add_paragraph(preview, style='Macro Text')
                    except:
                        doc.add_paragraph("Could not read contents.")

        if not files_found:
             doc.add_paragraph("No relevant source files found in this directory.")
             
        # Add page break after each major chapter
        doc.add_page_break()
        chapter_num += 1

    doc.add_heading(f'{chapter_num}. Appendix: Architecture Workflows', level=1)
    doc.add_paragraph("1. Ingestion: Logs arrive via collectors.")
    doc.add_paragraph("2. Normalization: Logs are standardized to a common JSON schema.")
    doc.add_paragraph("3. Enrichment: IPs/Hashes are sent to VirusTotal.")
    doc.add_paragraph("4. Correlation: The sliding window groups events based on thresholds.")
    doc.add_paragraph("5. Detection: Rule engine evaluates correlated events against detection logic.")
    doc.add_paragraph("6. Action Generation: Actions are generated and sanitized.")
    doc.add_paragraph("7. Execution: Playbooks run network/IoT/endpoint scripts via the registry.")
    
    doc.save('Rule-Based documentation - Full Detailed.docx')
    print("Documentation generated successfully.")

if __name__ == '__main__':
    create_massive_doc()
