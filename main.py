import os
import hashlib
import requests
import subprocess
import shlex
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from datetime import datetime
import re
import string
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, Frame, PageTemplate
)

""" Configuration """
VT_API_KEY = ''
GOOGLE_AI_API_KEY = ''
genai.configure(api_key=GOOGLE_AI_API_KEY)
AI_MODEL_NAME = "gemini-1.5-flash-latest"
DIEC_PATH = r''
MIN_STRING_LENGTH = 7 


def compute_hashes(filepath):
    hashes = {'md5': hashlib.md5(), 'sha1': hashlib.sha1(), 'sha256': hashlib.sha256()}
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            for h in hashes.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in hashes.items()}


def query_virustotal(file_hash):
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {'x-apikey': VT_API_KEY}
    try:
        r = requests.get(url, headers=headers)
        if r.status_code != 200:
            return None
        data = r.json().get('data', {}).get('attributes', {})
    except Exception:
        return None
    stats = data.get('last_analysis_stats', {})
    total = sum(stats.values()); mal = stats.get('malicious', 0)
    return {
        'detection_ratio': f"{mal}/{total} engines flagged this file",
        'file_size': data.get('size', 0),
        'type_desc': data.get('type_description', 'N/A'),
        'mime': data.get('mime_type', 'N/A'),
        'tags': ', '.join(data.get('tags', [])),
        'first_sub': datetime.utcfromtimestamp(data.get('first_submission_date', 0)).strftime('%Y-%m-%d'),
        'last_analyzed': datetime.utcfromtimestamp(data.get('last_analysis_date', 0)).strftime('%Y-%m-%d'),
        'threat_label': data.get('meaningful_name', 'N/A'),
        'votes': data.get('votes', {})
    }


def analyze_with_die(filepath):
    cmd = [DIEC_PATH, '--heuristicscan', filepath]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return proc.stdout.strip() or 'No packer detected.'
    except PermissionError:
        return 'Access denied: ensure Diec.exe is unblocked and run as Administrator.'
    except Exception as e:
        return f'Error running Diec: {e}'


def is_meaningful(s):
    if len(s) < 8:
        return False
    if len(set(s)) <= 4:
        return False
    return True


STRINGS_EXE_PATH = r""  # adjust to your install location

def extract_strings(filepath):
    """
    Uses Sysinternals 'strings.exe' to dump readable strings from a binary,
    then filters them through is_meaningful().
    """
    # Build the command:
    # -nobanner  → suppress banner
    # -n <len>  → set minimum string length
    cmd = [
        STRINGS_EXE_PATH,
        "-nobanner",
        "-n", str(MIN_STRING_LENGTH),
        filepath
    ]

    try:
        # Run strings.exe and capture its stdout (text mode)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
    except subprocess.TimeoutExpired:
        return "Error: strings.exe timed out."
    except Exception as e:
        return f"Error running strings.exe: {e}"

    # Split output into lines and filter
    lines = proc.stdout.splitlines()
    meaningful = [
        line for line in lines
        if is_meaningful(line)
    ]

    # Return as a single newline‑joined string
    return "\n".join(meaningful) or "No meaningful strings found."

 

def ask_google_ai(prompt):
    """Send prompt to Google AI for text generation."""
    try:
        model = genai.GenerativeModel(AI_MODEL_NAME)
        # Optional: Configure safety settings
        # These are example settings; adjust as needed.
        safety_settings = {
            HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
            HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
        }

        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig( # Use genai.types.GenerationConfig
                temperature=0.2,
                max_output_tokens=512
            ),
            safety_settings=safety_settings # Pass safety settings here
        )

        # Check if the response has parts and text
        if response.parts:
            return response.text
        elif response.prompt_feedback and response.prompt_feedback.block_reason:
            block_reason_message = getattr(response.prompt_feedback, 'block_reason_message', 'No specific message.')
            return f"[ERROR calling Google AI]: Content blocked due to {response.prompt_feedback.block_reason}. Message: {block_reason_message}"
        else:
            # This case might occur if the response is empty for other reasons
            # or if the model couldn't generate content based on the prompt.
            return "[ERROR calling Google AI]: Received an empty or unexpected response from the model."

    except AttributeError as e:
        # This can happen if the response object is not what's expected (e.g., None due to API key issue before even making a call)
        if "'NoneType' object has no attribute 'parts'" in str(e) or \
           "'NoneType' object has no attribute 'text'" in str(e) or \
           "'NoneType' object has no attribute 'prompt_feedback'" in str(e):
            return f"[ERROR calling Google AI]: Model '{AI_MODEL_NAME}' might not be available, or the API key is invalid/misconfigured. Response was None. Original error: {e}"
        return f'[ERROR calling Google AI - AttributeError]: {e}'
    except Exception as e:
        # General exception for API errors, network issues, etc.
        return f'[ERROR calling Google AI - General Exception]: {e}'

""" PDF Generation """

def header_footer(canvas, doc):
    # Draw header
    canvas.saveState()
    canvas.setFont('Helvetica-Bold', 10)
    canvas.drawString(15*mm, A4[1] - 15*mm, "Malware Analysis Report")
    # Draw footer
    canvas.setFont('Helvetica', 8)
    canvas.drawRightString(A4[0] - 15*mm, 15*mm, f"Page {doc.page}")
    canvas.restoreState()

def generate_pdf(reports, out_path):
    doc = SimpleDocTemplate(
        out_path,
        pagesize=A4,
        leftMargin=15*mm,
        rightMargin=15*mm,
        topMargin=25*mm,
        bottomMargin=25*mm
    )

    # Base stylesheet
    styles = getSampleStyleSheet()
    # Custom styles
    styles.add(ParagraphStyle(
        name='FileTitle',
        parent=styles['Heading2'],
        spaceAfter=6,
        textColor=colors.darkblue
    ))
    styles.add(ParagraphStyle(
        name='SectionHeader',
        parent=styles['Heading4'],
        textColor=colors.HexColor('#333333'),
        spaceBefore=8,
        spaceAfter=4
    ))
    # Rename the body style to avoid conflict
    styles.add(ParagraphStyle(
        name='CustomBodyText',
        parent=styles['BodyText'],
        fontSize=9,
        leading=12
    ))

    elements = []

    for rep in reports:
        filename = os.path.basename(rep['file'])
        elements.append(Paragraph(filename, styles['FileTitle']))

        # Hash table
        hash_data = [
            ['MD5', rep['hashes']['md5']],
            ['SHA1', rep['hashes']['sha1']],
            ['SHA256', rep['hashes']['sha256']],
        ]
        t = Table(hash_data, colWidths=[30*mm, 120*mm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('BOX', (0,0), (-1,-1), 0.5, colors.grey),
            ('INNERGRID', (0,0), (-1,-1), 0.25, colors.grey),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 4))

        # VirusTotal section
        elements.append(Paragraph('VirusTotal Details', styles['SectionHeader']))
        vt = rep.get('vt')
        vt_data = []
        if vt:
            vt_data = [
                ['Detection Ratio', vt['detection_ratio']],
                ['File Size', f"{vt['file_size']} bytes"],
                ['Type', vt['type_desc']],
                ['MIME Type', vt['mime']],
                ['First Submitted', vt['first_sub']],
                ['Last Analyzed', vt['last_analyzed']],
                ['Label', vt['threat_label']],
                ['Votes (H/M)', f"{vt['votes'].get('harmless',0)} / {vt['votes'].get('malicious',0)}"],
            ]
        else:
            vt_data = [['VirusTotal', 'N/A']]
        vt_table = Table(vt_data, colWidths=[40*mm, 110*mm])
        vt_table.setStyle(TableStyle([
            ('BOX', (0,0), (-1,-1), 0.5, colors.grey),
            ('INNERGRID', (0,0), (-1,-1), 0.25, colors.grey),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ]))
        elements.append(vt_table)
        elements.append(Spacer(1, 6))

        # Other text sections
        for title, key in [
            ('Detect It Easy', 'die'),
            ('Extracted Strings', 'strings'),
            ('AI Analysis', 'analysis')
        ]:
            elements.append(Paragraph(title, styles['SectionHeader']))
            for line in rep.get(key, '').splitlines():
                elements.append(Paragraph(line, styles['CustomBodyText']))
            elements.append(Spacer(1, 6))

        elements.append(PageBreak())

    # Add header/footer template
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id='normal')
    template = PageTemplate(id='withHeaderFooter', frames=[frame], onPage=header_footer)
    doc.addPageTemplates([template])

    doc.build(elements)


# === GUI ===
class App:
    def __init__(self, master):
        # Use a modern ttkbootstrap theme
        self.style = tb.Style(theme='solar')  # try 'solar', 'darkly', 'flatly', etc.
        self.master = master
        master.title('🔍 Malware Analysis Tool')
        master.geometry('900x400')
        master.minsize(600, 350)

        # Create main frame
        container = tb.Frame(master, padding=(20, 20))
        container.pack(fill=BOTH, expand=YES)

        # Title label
        title = tb.Label(container, text='Malware Analysis Tool', font=('Helvetica', 18, 'bold'), bootstyle='info')
        title.pack(pady=(0, 10))

        # Folder selection
        folder_frame = tb.Frame(container)
        folder_frame.pack(fill=X, pady=10)
        lbl = tb.Label(folder_frame, text='Select folder containing malware samples:', font=('Helvetica', 12))
        lbl.pack(side=LEFT, padx=(0, 10))

        self.folder_entry = tb.Entry(folder_frame, width=40, state='readonly', bootstyle='secondary')
        self.folder_entry.pack(side=LEFT, padx=(0, 10))

        browse_btn = tb.Button(folder_frame, text='Browse', command=self.browse, bootstyle='primary')
        browse_btn.pack(side=LEFT)

        # Progress bar
        self.progress = tb.Progressbar(container, length=500, mode='determinate', bootstyle='success')
        self.progress.pack(pady=15)

        # Analyze button
        self.analyze_btn = tb.Button(container, text='Analyze & Export PDF', state=DISABLED, command=self.run, bootstyle='danger')
        self.analyze_btn.pack(pady=10)

        # Status text
        self.status = tb.Label(container, text='No folder selected.', font=('Helvetica', 10), bootstyle='secondary')
        self.status.pack(pady=(10,0))

    def browse(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder = folder
            self.folder_entry.config(state='normal')
            self.folder_entry.delete(0, tk.END)
            self.folder_entry.insert(0, folder)
            self.folder_entry.config(state='readonly')
            self.analyze_btn.config(state=NORMAL)
            self.status.config(text='📂 Folder selected', bootstyle='success')
        else:
            self.analyze_btn.config(state=DISABLED)
            self.status.config(text='❌ No folder selected', bootstyle='warning')

    def run(self):
        # Reset progress
        files = [os.path.join(self.folder, f) for f in os.listdir(self.folder)
                 if os.path.isfile(os.path.join(self.folder, f))]
        total = len(files)
        if total == 0:
            messagebox.showwarning('No Files', 'The selected folder has no files.')
            return

        self.progress['maximum'] = total
        self.progress['value'] = 0
        self.analyze_btn.config(state=DISABLED)
        self.status.config(text='🔄 Analysis in progress...', bootstyle='info')
        self.master.update_idletasks()

        reports = []
        for i, fp in enumerate(files, start=1):
            # perform analysis
            hashes = compute_hashes(fp)
            vt = query_virustotal(hashes['sha256'])
            die_out = analyze_with_die(fp)
            strings = extract_strings(fp)
            detection_str = vt['detection_ratio'] if vt else 'N/A'
            prompt = (
                f"File: {os.path.basename(fp)}\n"
                f"Hashes: MD5={hashes['md5']}, SHA1={hashes['sha1']}, SHA256={hashes['sha256']}\n"
                f"VT detection: {detection_str}\n"
                f"Extracted Strings:\n{strings[:1000]}"
            )
            analysis = ask_google_ai(prompt).replace('*', '')
            reports.append({
                'file': fp,
                'hashes': hashes,
                'vt': vt,
                'die': die_out,
                'strings': strings,
                'analysis': analysis
            })

            # update progress
            self.progress['value'] = i
            self.master.update_idletasks()

        # Save PDF
        save_path = filedialog.asksaveasfilename(defaultextension='.pdf', filetypes=[('PDF Files', '*.pdf')])
        if save_path:
            generate_pdf(reports, save_path)
            messagebox.showinfo('✅ Completed', f'Report saved to:\n{save_path}')
            self.status.config(text='✅ Analysis completed successfully.', bootstyle='success')
        else:
            self.status.config(text='❌ PDF export canceled.', bootstyle='danger')

        self.analyze_btn.config(state=NORMAL)
        self.progress['value'] = 0

if __name__ == '__main__':
    root = tb.Window()
    app = App(root)
    root.mainloop()