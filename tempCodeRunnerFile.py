from flask import Flask, render_template, request, send_file
from scanner import WebAppScanner
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

app = Flask(__name__)

# Home Page
@app.route('/')
def home():
    return render_template('home.html')

# Scanner Page
@app.route('/scanner', methods=['GET', 'POST'])
def scanner():
    results = None
    url = ""
    if request.method == 'POST':
        url = request.form['url']
        scan_type = request.form['scan']
        
        # Initialize the scanner for the provided URL
        scanner = WebAppScanner(url)
        
        # Scan based on the type selected
        if scan_type == 'sql_injection':
            results = [scanner.detect_sql_injection(url)]
        elif scan_type == 'xss':
            results = [scanner.detect_xss(url)]
        elif scan_type == 'csrf':
            response = scanner.send_request(url)
            if response:
                forms = scanner.find_forms(response.text)
                results = [scanner.detect_csrf(forms)]
            else:
                results = ["Failed to fetch the URL."]
    
    return render_template('scanner.html', url=url, results=results)

# Generate PDF Report
@app.route('/generate_report', methods=['POST'])
def generate_report():
    # Extract URL and results from the form
    url = request.form['url']
    results = request.form.getlist('results')

    # Create a PDF report in memory
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.drawString(100, 750, f"Website Security Scan Report for: {url}")
    p.drawString(100, 725, "Scan Results:")

    # Add scan results to the PDF
    y = 700
    for result in results:
        p.drawString(100, y, f"- {result}")
        y -= 25

    p.showPage()
    p.save()
    
    buffer.seek(0)
    
    # Send the PDF report to the user for download
    return send_file(buffer, as_attachment=True, download_name="security_scan_report.pdf", mimetype='application/pdf')

# About Page
@app.route('/about')
def about():
    return render_template('about.html')

# Contact Page
@app.route('/contact')
def contact():
    return render_template('contact.html')

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)
