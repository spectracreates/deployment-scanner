import os
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors

from config import Config
from static_engine import StaticAnalyzer
from ai_layer import AIAnalyzer

app = Flask(__name__)
app.config['SECRET_KEY'] = Config.SECRET_KEY
app.config['UPLOAD_FOLDER'] = Config.UPLOAD_FOLDER
app.config['REPORT_FOLDER'] = Config.REPORT_FOLDER
app.config['MAX_CONTENT_LENGTH'] = Config.MAX_FILE_SIZE

# Ensure directories exist
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(Config.REPORT_FOLDER, exist_ok=True)

def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Main page."""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_file():
    """Handle file upload and scanning."""
    
    # Validate file upload
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': f'Invalid file type. Allowed: {Config.ALLOWED_EXTENSIONS}'}), 400
    
    try:
        # Save uploaded file
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        saved_filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
        file.save(filepath)
        
        # Read file content
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Run static analysis
        static_analyzer = StaticAnalyzer()
        findings = static_analyzer.analyze_file(filename, content)
        findings_dict = [f.to_dict() for f in findings]
        
        # Run AI analysis
        ai_analyzer = AIAnalyzer()
        file_type = 'Kubernetes YAML' if filename.endswith(('.yaml', '.yml')) else \
                   'Terraform' if filename.endswith('.tf') else \
                   'Dockerfile'
        
        ai_results = ai_analyzer.analyze_findings(findings_dict, content, file_type)
        
        # Generate diff
        diff = ai_analyzer.generate_diff(content, ai_results['improved_config'])
        
        # Prepare response
        response = {
            'success': True,
            'filename': filename,
            'scan_time': timestamp,
            'file_type': file_type,
            'findings_count': len(findings_dict),
            'findings': findings_dict,
            'ai_analysis': {
                'diagnosis': ai_results['diagnosis'],
                'severity_justification': ai_results['severity_justification'],
                'remediation_steps': ai_results['remediation_steps'],
                'overall_risk_score': ai_results['overall_risk_score']
            },
            'diff': diff,
            'improved_config': ai_results['improved_config'],
            'original_config': content
        }
        
        # Save report as JSON
        report_filename = f"report_{timestamp}_{filename}.json"
        report_path = os.path.join(app.config['REPORT_FOLDER'], report_filename)
        with open(report_path, 'w') as rf:
            json.dump(response, rf, indent=2)
        
        response['report_id'] = report_filename
        
        return jsonify(response)
    
    except Exception as e:
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500

@app.route('/export/<report_id>/json')
def export_json(report_id):
    """Export report as JSON."""
    try:
        report_path = os.path.join(app.config['REPORT_FOLDER'], report_id)
        if not os.path.exists(report_path):
            return jsonify({'error': 'Report not found'}), 404
        
        return send_file(report_path, as_attachment=True, download_name=report_id)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/export/<report_id>/pdf')
def export_pdf(report_id):
    """Export report as PDF."""
    try:
        report_path = os.path.join(app.config['REPORT_FOLDER'], report_id)
        if not os.path.exists(report_path):
            return jsonify({'error': 'Report not found'}), 404
        
        # Load JSON report
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        # Generate PDF
        pdf_filename = report_id.replace('.json', '.pdf')
        pdf_path = os.path.join(app.config['REPORT_FOLDER'], pdf_filename)
        
        generate_pdf_report(data, pdf_path)
        
        return send_file(pdf_path, as_attachment=True, download_name=pdf_filename)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for CI/CD integration."""
    
    # Check for JSON payload
    if request.is_json:
        data = request.json
        config_content = data.get('config')
        file_type = data.get('file_type', 'yaml')
        
        if not config_content:
            return jsonify({'error': 'No config content provided'}), 400
        
        # Create temporary filename
        filename = f"api_upload.{file_type}"
        
    # Check for file upload
    elif 'file' in request.files:
        file = request.files['file']
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type'}), 400
        
        filename = secure_filename(file.filename)
        config_content = file.read().decode('utf-8')
    
    else:
        return jsonify({'error': 'No config provided'}), 400
    
    try:
        # Run static analysis
        static_analyzer = StaticAnalyzer()
        findings = static_analyzer.analyze_file(filename, config_content)
        findings_dict = [f.to_dict() for f in findings]
        
        # Run AI analysis
        ai_analyzer = AIAnalyzer()
        file_type_name = 'Kubernetes YAML' if filename.endswith(('.yaml', '.yml')) else \
                        'Terraform' if filename.endswith('.tf') else \
                        'Dockerfile'
        
        ai_results = ai_analyzer.analyze_findings(findings_dict, config_content, file_type_name)
        
        # Return simplified response for API
        return jsonify({
            'success': True,
            'findings_count': len(findings_dict),
            'risk_score': ai_results['overall_risk_score'],
            'findings': findings_dict,
            'diagnosis': ai_results['diagnosis'],
            'remediation_steps': ai_results['remediation_steps']
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def generate_pdf_report(data, output_path):
    """Generate PDF report from scan results."""
    
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=30
    )
    story.append(Paragraph("Security Scan Report", title_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Metadata
    metadata = [
        ['File:', data['filename']],
        ['Scan Time:', data['scan_time']],
        ['File Type:', data['file_type']],
        ['Findings:', str(data['findings_count'])],
        ['Risk Score:', f"{data['ai_analysis']['overall_risk_score']}/100"]
    ]
    
    meta_table = Table(metadata, colWidths=[2*inch, 4*inch])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.grey),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.3*inch))
    
    # AI Diagnosis
    story.append(Paragraph("Executive Summary", styles['Heading2']))
    story.append(Paragraph(data['ai_analysis']['diagnosis'], styles['BodyText']))
    story.append(Spacer(1, 0.2*inch))
    
    # Severity Justification
    story.append(Paragraph("Risk Assessment", styles['Heading2']))
    story.append(Paragraph(data['ai_analysis']['severity_justification'], styles['BodyText']))
    story.append(Spacer(1, 0.2*inch))
    
    # Remediation Steps
    story.append(Paragraph("Remediation Steps", styles['Heading2']))
    for idx, step in enumerate(data['ai_analysis']['remediation_steps'], 1):
        story.append(Paragraph(f"{idx}. {step}", styles['BodyText']))
        story.append(Spacer(1, 0.1*inch))
    
    story.append(PageBreak())
    
    # Detailed Findings
    story.append(Paragraph("Detailed Findings", styles['Heading2']))
    story.append(Spacer(1, 0.1*inch))
    
    for finding in data['findings']:
        story.append(Paragraph(f"<b>Issue ID:</b> {finding['issue_id']}", styles['BodyText']))
        story.append(Paragraph(f"<b>Description:</b> {finding['description']}", styles['BodyText']))
        story.append(Paragraph(f"<b>Location:</b> {finding['location']}", styles['BodyText']))
        story.append(Paragraph(f"<b>Severity:</b> {finding['severity_guess']}", styles['BodyText']))
        story.append(Paragraph(f"<b>Category:</b> {finding['rule_category']}", styles['BodyText']))
        story.append(Spacer(1, 0.2*inch))
    
    doc.build(story)
if __name__ == '__main__':
    # Validate configuration
    try:
        Config.validate()
        print(f"✓ Configuration validated")
        print(f"✓ Using LLM model: {Config.LLM_MODEL}")
        print(f"✓ API endpoint: {Config.OPENAI_BASE_URL}")
    except ValueError as e:
        print(f"✗ Configuration error: {e}")
        print("Please check your .env file")
        exit(1)
    
    print("\n" + "="*60)
    print("Deployment Risk Scanner")
    print("="*60)
    print(f"Server starting at: http://127.0.0.1:5000")
    print(f"Upload folder: {Config.UPLOAD_FOLDER}")
    print(f"Report folder: {Config.REPORT_FOLDER}")
    print("="*60 + "\n")
    
    if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))

    app.run(debug=False, host='0.0.0.0', port=port)
