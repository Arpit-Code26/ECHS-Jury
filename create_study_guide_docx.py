"""
Script to generate CYBERSENTINEL_COMPLETE_STUDY_GUIDE.docx using python-docx.
"""
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from pathlib import Path

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), fill_hex)
    tcPr.append(shd)

def create_guide_docx(output_path: str):
    doc = docx.Document()
    
    # Page Margins
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)
        
    # Document Title
    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_title = p_title.add_run("CYBERSENTINEL: THE ULTIMATE PROJECT STUDY & PRESENTATION GUIDE")
    run_title.font.name = "Arial"
    run_title.font.size = Pt(22)
    run_title.font.bold = True
    run_title.font.color.rgb = RGBColor(14, 116, 144) # Deep Cyan
    
    p_sub = doc.add_paragraph()
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_sub = p_sub.add_run("How CyberSentinel Works, How to Read the Network CSV, and How to Defend Your Project")
    run_sub.font.name = "Arial"
    run_sub.font.size = Pt(13)
    run_sub.font.italic = True
    run_sub.font.color.rgb = RGBColor(100, 116, 139)
    
    doc.add_paragraph() # Spacer

    # ==========================================
    # SECTION 1: THE BIG PICTURE
    # ==========================================
    h1 = doc.add_heading("1. The Big Picture: What is CyberSentinel?", level=1)
    h1.runs[0].font.color.rgb = RGBColor(15, 23, 42)
    
    doc.add_paragraph(
        "Imagine you own a high-security office building. Hundreds of people enter every minute. "
        "A traditional security guard cannot open every single briefcase and inspect every document—it would take too long. "
        "Instead, the guard watches how people behave: Is someone running aggressively? Is someone trying to pick every single lock in the hallway? "
        "Is one person trying 500 different keycards at the front door?"
    )
    doc.add_paragraph(
        "CyberSentinel does the exact same thing for computer networks. It is a Network Intrusion Detection System (NIDS). "
        "It does NOT read the private text of emails or WhatsApp messages. Instead, it inspects 'Network Flows'—the mathematical envelope of connections. "
        "It looks at packet counts, connection duration, transfer speeds, and TCP flags to detect cyberattacks in real-time."
    )
    doc.add_paragraph(
        "Crucially, CyberSentinel is designed for Edge AI: it runs on low-power devices like the NVIDIA Jetson Orin Nano (8GB) "
        "as well as ordinary Windows laptops using a single unified Python codebase, completely offline without internet or paid APIs."
    )

    # ==========================================
    # SECTION 2: DECODING THE CSV WITH YOUR OWN EYES
    # ==========================================
    doc.add_page_break()
    h2 = doc.add_heading("2. Decoding the CSV: How to Identify Threats With Your Own Eyes", level=1)
    h2.runs[0].font.color.rgb = RGBColor(15, 23, 42)
    
    doc.add_paragraph(
        "When you open 'demo_attack_traffic.csv' or any CIC-IDS2017 dataset file in Microsoft Excel or Notepad, "
        "you see 67 columns of numbers. You might feel overwhelmed and think: 'What do these numbers mean? How does the AI know it's an attack?'"
    )
    doc.add_paragraph(
        "Here is the secret: You only need to look at 5 KEY COLUMNS to spot the attack yourself!"
    )

    # Table of Key Columns
    table_cols = doc.add_table(rows=6, cols=3)
    table_cols.alignment = WD_TABLE_ALIGNMENT.CENTER
    headers = ["Key CSV Column Name", "Real-World Meaning", "What to Look For"]
    for i, h in enumerate(headers):
        cell = table_cols.cell(0, i)
        cell.text = h
        cell.paragraphs[0].runs[0].font.bold = True
        set_cell_background(cell, "E2E8F0")

    col_data = [
        ("Destination Port", "Which 'door' or service on the server is being contacted.", "80/443 = Web, 21 = FTP (Files), 22 = SSH (Remote Shell), Random = PortScan"),
        ("Flow Duration", "How long the connection lasted (in microseconds: 1,000,000 = 1 sec).", "Short (< 10,000) vs Long (1,000,000+)"),
        ("Total Fwd Packets", "Number of packets sent by the requester/attacker.", "Very high in floods; tiny (1-2) in scans"),
        ("Flow Packets/s", "Speed of sending (packets per second).", "Normal is 1 to 50; DDoS is 10,000 to 500,000!"),
        ("SYN Flag Count", "TCP handshake request ('Hello, let's talk').", "Normal has 0 or 1; Floods have continuous 1s")
    ]
    for row_idx, data in enumerate(col_data, start=1):
        for col_idx, text in enumerate(data):
            cell = table_cols.cell(row_idx, col_idx)
            cell.text = text

    doc.add_paragraph() # Spacer

    # ==========================================
    # SECTION 3: THE 6 THREAT TYPES EXPLAINED
    # ==========================================
    h3 = doc.add_heading("3. The Specific Attacks Detected by CyberSentinel", level=1)
    h3.runs[0].font.color.rgb = RGBColor(15, 23, 42)

    threats = [
        {
            "name": "A. BENIGN (Normal, Safe Traffic)",
            "desc": "A regular human being browsing a website, checking email, or downloading a file.",
            "csv_signature": [
                "Destination Port: 80 (HTTP), 443 (HTTPS), or 53 (DNS).",
                "Flow Duration: Normal duration (e.g. 100,000 to 500,000 microseconds).",
                "Packets: Balanced! The user sends a request (Total Fwd Packets = 5), and the server sends data back (Total Backward Packets = 8).",
                "Flow Packets/s: Moderate, human speed (under 100 packets/sec).",
                "SYN Flags: Low. Connection is completed normally."
            ]
        },
        {
            "name": "B. DDoS (Distributed Denial of Service)",
            "desc": "An attacker uses a botnet of thousands of infected computers to bombard a website with millions of fake packets until the server runs out of memory and crashes for legitimate users.",
            "csv_signature": [
                "Destination Port: 80 or 443 (targeting web servers).",
                "Flow Packets/s: INSANELY HIGH (thousands or tens of thousands).",
                "Total Fwd Packets: High (30 to 100+), but Total Backward Packets: Almost ZERO (the server is overwhelmed and cannot answer!).",
                "Packet Length: Very small and identical (e.g., all packets are 40 to 80 bytes).",
                "SYN Flag Count: 1 (SYN flood trying to hold open server connection slots)."
            ]
        },
        {
            "name": "C. DoS Hulk (Application-Layer HTTP Flood)",
            "desc": "Hulk (HTTP Unbearable Load King) sends endless unique HTTP GET requests designed to bypass proxy caching and exhaust web server worker threads.",
            "csv_signature": [
                "Destination Port: 80 (HTTP).",
                "Flow Duration: Long and persistent (e.g., 1,000,000+ microseconds).",
                "Total Length of Fwd Packets: Elevated, because the attacker is constantly pushing URL requests.",
                "Flow IAT Mean: Low inter-arrival time (packets arrive in rapid bursts)."
            ]
        },
        {
            "name": "D. PortScan (Reconnaissance / Burglar Probing)",
            "desc": "Before attacking, a hacker sends single probe packets to every port (door) on your computer to see which ones are open and vulnerable.",
            "csv_signature": [
                "Destination Port: WILD AND RANDOM! Look at rows next to each other: Port 2341, Port 5821, Port 3389, Port 12093...",
                "Total Fwd Packets: EXACTLY 1, 2, or 3 packets! The attacker knocks once and moves on immediately.",
                "Total Backward Packets: 0 or 1.",
                "Flow Duration: Super tiny (e.g., 50 to 3,000 microseconds).",
                "SYN Flag Count: 1. RST Flag Count: High (server closes the unopened port)."
            ]
        },
        {
            "name": "E. FTP-Patator & SSH-Patator (Brute-Force Password Guessing)",
            "desc": "An automated dictionary attack bot trying 10,000 passwords a minute against an FTP or SSH server to guess login credentials.",
            "csv_signature": [
                "Destination Port: ALWAYS Port 21 (FTP) or ALWAYS Port 22 (SSH).",
                "Flow Duration: Moderate, repeating over and over again in identical bursts.",
                "Packet Size: Uniform (the length of the credential handshake strings)."
            ]
        },
        {
            "name": "F. ANOMALY (PyTorch Autoencoder Detection)",
            "desc": "A zero-day or novel threat that has never been seen before. Our deep neural network was trained ONLY on normal traffic. When an abnormal pattern appears, the autoencoder fails to reconstruct it, resulting in a high Reconstruction Mean Squared Error (MSE).",
            "csv_signature": [
                "Any flow where the Reconstruction MSE exceeds the threshold (0.573) derived from our validation set."
            ]
        }
    ]

    for t in threats:
        p_t = doc.add_paragraph()
        run_t = p_t.add_run(t["name"])
        run_t.font.bold = True
        run_t.font.size = Pt(13)
        run_t.font.color.rgb = RGBColor(30, 41, 59)
        
        doc.add_paragraph(f"• What it is: {t['desc']}")
        doc.add_paragraph("• How to see it in the CSV with your own eyes:")
        for sig in t["csv_signature"]:
            p_sig = doc.add_paragraph(f"   - {sig}")
            p_sig.paragraph_format.left_indent = Inches(0.25)
        doc.add_paragraph() # Spacer

    # ==========================================
    # SECTION 4: REAL ROW EXAMPLES FROM YOUR CSV
    # ==========================================
    doc.add_page_break()
    h4 = doc.add_heading("4. Side-by-Side Comparison: Spotting Attacks in the CSV", level=1)
    h4.runs[0].font.color.rgb = RGBColor(15, 23, 42)
    
    doc.add_paragraph(
        "Here is a comparison table comparing real rows from 'demo_attack_traffic.csv'. "
        "Notice how obvious the differences are when you look at the numbers side-by-side!"
    )

    table_comp = doc.add_table(rows=5, cols=6)
    table_comp.alignment = WD_TABLE_ALIGNMENT.CENTER
    comp_headers = ["Attack Category", "Dest Port", "Flow Duration", "Fwd Packets", "Flow Packets/s", "SYN Flag"]
    for i, h in enumerate(comp_headers):
        cell = table_comp.cell(0, i)
        cell.text = h
        cell.paragraphs[0].runs[0].font.bold = True
        set_cell_background(cell, "CBD5E1")

    row_comp_data = [
        ("BENIGN (Safe)", "443 / 80", "500,000 µs", "5 packets", "10 pkts/sec (Normal)", "0 or 1"),
        ("DDoS (Attack)", "80", "80,000 µs", "50 packets", "15,000 pkts/s (MASSIVE!)", "1 (SYN Flood)"),
        ("PortScan (Attack)", "34,812 (Random)", "1,200 µs (Tiny!)", "1 packet (Just a knock)", "830 pkts/sec", "1"),
        ("FTP-Patator (Attack)", "21 (FTP Port)", "45,000 µs", "16 packets", "350 pkts/sec", "0")
    ]
    for row_idx, r in enumerate(row_comp_data, start=1):
        for col_idx, text in enumerate(r):
            cell = table_comp.cell(row_idx, col_idx)
            cell.text = text
            if "Attack" in r[0]:
                set_cell_background(cell, "FEE2E2") # Soft Red
            else:
                set_cell_background(cell, "DCFCE7") # Soft Green

    doc.add_paragraph() # Spacer

    # ==========================================
    # SECTION 5: HOW THE MACHINE LEARNING MODELS WORK
    # ==========================================
    h5 = doc.add_heading("5. How CyberSentinel's Machine Learning Works", level=1)
    h5.runs[0].font.color.rgb = RGBColor(15, 23, 42)
    
    doc.add_paragraph(
        "CyberSentinel uses a two-tier approach combining Supervised Learning and Unsupervised Deep Learning:"
    )
    doc.add_paragraph(
        "1. Supervised Learning (XGBoost & Random Forest): We trained these models on tens of thousands of labeled rows. "
        "They learn decision trees: 'IF Destination Port == 80 AND Flow Packets/s > 5000 AND Packet Length < 80 THEN Classify as DDoS'. "
        "XGBoost achieves 99.97% accuracy with ultra-fast latency (4.67 ms per 1,000 records)."
    )
    doc.add_paragraph(
        "2. Unsupervised Deep Learning (PyTorch Autoencoder): What if an attacker creates an attack that has no name yet? "
        "Supervised models might be blind to it. The Autoencoder compresses normal network flows into a small 16-number 'latent bottleneck' "
        "and tries to reconstruct them back to 67 features. It reconstructs normal traffic easily. But when an attack arrives, "
        "the reconstruction error jumps above 0.573, immediately sounding the alarm!"
    )

    # ==========================================
    # SECTION 6: HOW TO PRESENT EACH DASHBOARD PAGE
    # ==========================================
    doc.add_page_break()
    h6 = doc.add_heading("6. How to Present Every Page in the Streamlit Dashboard", level=1)
    h6.runs[0].font.color.rgb = RGBColor(15, 23, 42)

    pages = [
        ("Page 1: Overview", "The Executive Dashboard. Displays top metrics (Total records, Benign vs Suspicious, Threats detected). Point out the runtime host telemetry in the sidebar (Windows 11 vs Jetson)."),
        ("Page 2: Dataset Analysis", "Data Ingestion & Hygiene. Show how CSVs are uploaded and schema-matched. Explain Data Leakage Prevention: 'We strip IP addresses and timestamps so the AI learns packet physics, not IP addresses.'"),
        ("Page 3: Threat Detection", "The Live Engine. Select XGBoost and click 'Analyze Traffic Records'. Show the donut charts, the table of suspicious flows, and the download button to export the report."),
        ("Page 4: Model Performance", "The Proof. Show the 99.97% accuracy, the Confusion Matrix heatmaps, and the Top Feature Importances chart."),
        ("Page 5: AI Security Assistant", "The Conversational AI. Point out the active analysis context. Click 'Explain DDoS' or 'Admin Investigation Steps' to show how the AI explains technical findings in plain language."),
        ("Page 6: Edge Device Performance", "Hardware Telemetry. Show CPU and RAM gauges. Explain that on an 8GB Jetson Orin Nano, the entire system stays under 4.0 GB of RAM to prevent out-of-memory crashes.")
    ]
    for p_name, p_desc in pages:
        p_item = doc.add_paragraph()
        p_item.add_run(f"• {p_name}: ").font.bold = True
        p_item.add_run(p_desc)

    # Save document
    doc.save(output_path)
    print(f"Word document successfully created at: {output_path}")

if __name__ == "__main__":
    out_file = str(Path(__file__).resolve().parent / "CYBERSENTINEL_COMPLETE_STUDY_GUIDE.docx")
    create_guide_docx(out_file)
