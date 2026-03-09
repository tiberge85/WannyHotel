#!/usr/bin/env python3
"""Générateur de Devis/Proforma PDF — Format RAMYA TECHNOLOGIE"""

import os, json
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, white
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

TEAL = HexColor('#1a7a6d')
ORANGE = HexColor('#e8672a')


def number_to_words_fr(n):
    """Convertit un nombre en mots français (simplifié)."""
    units = ['', 'Un', 'Deux', 'Trois', 'Quatre', 'Cinq', 'Six', 'Sept', 'Huit', 'Neuf',
             'Dix', 'Onze', 'Douze', 'Treize', 'Quatorze', 'Quinze', 'Seize', 'Dix-sept',
             'Dix-huit', 'Dix-neuf']
    tens = ['', '', 'Vingt', 'Trente', 'Quarante', 'Cinquante', 'Soixante',
            'Soixante', 'Quatre-vingt', 'Quatre-vingt']
    
    if n == 0: return 'Zéro'
    if n < 0: return 'Moins ' + number_to_words_fr(-n)
    
    result = ''
    if n >= 1000000:
        m = n // 1000000
        result += ('Un Million' if m == 1 else number_to_words_fr(m) + ' Millions') + ' '
        n %= 1000000
    if n >= 1000:
        t = n // 1000
        result += ('Mille' if t == 1 else number_to_words_fr(t) + ' Mille') + ' '
        n %= 1000
    if n >= 100:
        c = n // 100
        result += ('Cent' if c == 1 else units[c] + ' Cent') + ' '
        n %= 100
    if n >= 20:
        d = n // 10
        if d == 7 or d == 9:
            result += tens[d] + '-' + units[10 + n % 10] + ' '
            n = 0
        else:
            result += tens[d]
            if n % 10 == 1 and d != 8:
                result += ' et Un '
            elif n % 10 > 0:
                result += '-' + units[n % 10] + ' '
            else:
                result += ' '
            n = 0
    if 0 < n < 20:
        result += units[n] + ' '
    
    return result.strip()


def fmt(amount):
    """Format number with thousands separator."""
    return f"{amount:,.0f}".replace(',', ' ')


def generate_devis_pdf(devis_data, output_path, logo_path=None):
    """Génère un PDF de devis/proforma au format RAMYA."""
    
    doc = SimpleDocTemplate(output_path, pagesize=A4,
        leftMargin=15*mm, rightMargin=15*mm, topMargin=12*mm, bottomMargin=20*mm)
    
    story = []
    
    # Styles
    s_title = ParagraphStyle('title', fontSize=28, fontName='Helvetica-Bold', 
                              alignment=TA_RIGHT, textColor=TEAL)
    s_ref = ParagraphStyle('ref', fontSize=10, alignment=TA_RIGHT, textColor=HexColor('#555'))
    s_normal = ParagraphStyle('normal', fontSize=10, leading=13)
    s_bold = ParagraphStyle('bold', fontSize=10, fontName='Helvetica-Bold')
    s_small = ParagraphStyle('small', fontSize=8, textColor=HexColor('#888'))
    s_center = ParagraphStyle('center', fontSize=9, alignment=TA_CENTER)
    s_right = ParagraphStyle('right', fontSize=10, alignment=TA_RIGHT)
    s_footer = ParagraphStyle('footer', fontSize=7, alignment=TA_CENTER, textColor=TEAL)
    
    doc_type = devis_data.get('doc_type', 'devis').upper()
    ref = devis_data.get('reference', '')
    date_str = devis_data.get('date', datetime.now().strftime('%d-%m-%Y'))
    contact = devis_data.get('contact_commercial', '')
    client_name = devis_data.get('client_name', '')
    client_code = devis_data.get('client_code', '')
    objet = devis_data.get('objet', '')
    items = json.loads(devis_data.get('items_json', '[]')) if isinstance(devis_data.get('items_json'), str) else devis_data.get('items_json', [])
    
    total_ht = devis_data.get('total_ht', 0)
    petites_fourn = devis_data.get('petites_fournitures', 0)
    total_ttc = devis_data.get('total_ttc', 0)
    main_oeuvre = devis_data.get('main_oeuvre', 0)
    remise = devis_data.get('remise', 0)
    
    # === HEADER ===
    header_data = [
        [Paragraph("<b>RAMYA<br/>TECHNOLOGIE &amp; INNOVATION</b>", 
                    ParagraphStyle('co', fontSize=12, fontName='Helvetica-Bold', textColor=TEAL)),
         Paragraph("""<font color='#1a7a6d'>■</font> <i>Caméras de surveillance,</i><br/>
         <font color='#1a7a6d'>■</font> <i>Clôture électrique,</i><br/>
         <font color='#1a7a6d'>■</font> <i>Kit visiophone alarme anti-intrusion,</i><br/>
         <font color='#1a7a6d'>■</font> <i>Domotique, Poignées intelligentes</i>""",
         ParagraphStyle('services', fontSize=9, textColor=ORANGE, leading=13))]
    ]
    ht = Table(header_data, colWidths=[90*mm, 90*mm])
    ht.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'TOP')]))
    story.append(ht)
    story.append(Spacer(1, 8*mm))
    
    # === DEVIS / PROFORMA title ===
    story.append(Paragraph(doc_type, s_title))
    story.append(Paragraph(f"# {ref}", s_ref))
    story.append(Paragraph(f"Date: {date_str}", s_ref))
    if contact:
        story.append(Paragraph(f"Contact commercial: {contact}", s_ref))
    story.append(Spacer(1, 8*mm))
    
    # === CLIENT ===
    story.append(Paragraph("<b>À</b>", s_normal))
    story.append(Paragraph(f"<b>{client_name}</b>", ParagraphStyle('cl', fontSize=12, fontName='Helvetica-Bold')))
    if client_code:
        story.append(Spacer(1, 3*mm))
        story.append(Paragraph(f"Code client: {client_code}", s_normal))
    story.append(Spacer(1, 4*mm))
    
    # === OBJET ===
    if objet:
        story.append(Paragraph(f"<b>Objet : {objet}</b>", s_bold))
    story.append(Spacer(1, 6*mm))
    
    # === TABLE DES ARTICLES ===
    hdrs = ['#', 'Désignation', 'Qté.', 'Prix unitaire', 'Remise', 'Montant HT']
    table_data = [[Paragraph(h, ParagraphStyle('th', fontSize=9, fontName='Helvetica-Bold', textColor=white)) for h in hdrs]]
    
    for item in items:
        desc = str(item.get('designation', ''))
        detail = str(item.get('detail', ''))
        full_desc = f"<b>{desc}</b>"
        if detail:
            full_desc += f"<br/>{detail}"
        
        qty = item.get('qty', 1)
        prix = item.get('prix', 0)
        rem = item.get('remise', 0)
        montant = qty * prix - rem
        
        table_data.append([
            Paragraph(str(item.get('num', '')), s_center),
            Paragraph(full_desc, ParagraphStyle('desc', fontSize=9, leading=12)),
            Paragraph(str(qty), s_center),
            Paragraph(fmt(prix), s_right),
            Paragraph(fmt(rem) if rem else '', s_right),
            Paragraph(fmt(montant), s_right),
        ])
    
    col_widths = [12*mm, 68*mm, 14*mm, 28*mm, 20*mm, 28*mm]
    t = Table(table_data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), TEAL),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, HexColor('#f8f8f8')]),
    ]))
    story.append(t)
    story.append(Spacer(1, 6*mm))
    
    # === TOTAUX ===
    total_pieces = total_ht - main_oeuvre
    total_brut = total_ht
    total_net = total_brut - remise
    
    totals = [
        ['', '', '', '', Paragraph("<b>Total HT</b>", s_right), Paragraph(f"<b>{fmt(total_ht)}XOF</b>", s_right)],
        ['', '', '', '', Paragraph("petites fournitures", s_right), Paragraph(f"{fmt(petites_fourn)}XOF", s_right)],
    ]
    tt = Table(totals, colWidths=col_widths)
    tt.setStyle(TableStyle([('LINEABOVE', (4, 0), (5, 0), 1, HexColor('#cccccc'))]))
    story.append(tt)
    
    # Total TTC bar
    ttc_data = [
        [Paragraph("<b>Total TTC</b>", ParagraphStyle('ttc', fontSize=12, fontName='Helvetica-Bold', textColor=white, alignment=TA_RIGHT)),
         Paragraph(f"<b>{fmt(total_ttc)}XOF</b>", ParagraphStyle('ttcv', fontSize=12, fontName='Helvetica-Bold', textColor=white, alignment=TA_RIGHT))]
    ]
    ttc_t = Table(ttc_data, colWidths=[140*mm, 30*mm])
    ttc_t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), ORANGE),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(ttc_t)
    story.append(Spacer(1, 4*mm))
    
    # === BARRE RÉSUMÉ ===
    summary_hdrs = ['TOTAL PIÈCES', "MAIN D'ŒUVRE", 'TOTAL BRUT', 'REMISE', 'TOTAL NET', 'PETITES FOURN.', 'TOTAL TTC']
    summary_vals = [fmt(total_pieces), fmt(main_oeuvre), fmt(total_brut), fmt(remise), fmt(total_net), fmt(petites_fourn), fmt(total_ttc)]
    
    s_hdr = ParagraphStyle('sh', fontSize=5, fontName='Helvetica-Bold', textColor=white, alignment=TA_CENTER)
    s_val = ParagraphStyle('sv', fontSize=7, fontName='Helvetica-Bold', textColor=white, alignment=TA_CENTER)
    
    bar_data = [
        [Paragraph(h, s_hdr) for h in summary_hdrs],
        [Paragraph(f"{v}XOF", s_val) for v in summary_vals],
    ]
    bar = Table(bar_data, colWidths=[24*mm]*7)
    bar.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), TEAL),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#0d6b5e')),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(bar)
    story.append(Spacer(1, 5*mm))
    
    # === MONTANT EN LETTRES ===
    words = number_to_words_fr(int(total_ttc))
    story.append(Paragraph(
        f"<i>Sauf erreur, arrêté à la somme de: <b>{words} Francs CFA</b></i>",
        ParagraphStyle('words', fontSize=9, alignment=TA_CENTER, textColor=TEAL)
    ))
    story.append(Spacer(1, 15*mm))
    
    # === SIGNATURES ===
    sig_data = [
        [Paragraph("Note:", s_bold), '', Paragraph("Visa Client", s_bold)],
        [Paragraph("MODE DE REGLEMENT (Espèce, Chèque, Virement, Mobile money)", s_small), '', ''],
        ['', '', ''],
        [Paragraph("Signature autorisée", s_bold), '', ''],
    ]
    sig = Table(sig_data, colWidths=[85*mm, 15*mm, 70*mm], rowHeights=[12*mm, 8*mm, 20*mm, 8*mm])
    sig.setStyle(TableStyle([('VALIGN', (0, 0), (-1, -1), 'TOP')]))
    story.append(sig)
    story.append(Spacer(1, 10*mm))
    
    # === FOOTER ===
    story.append(Paragraph(
        "<b>Siège social ABIDJAN Cocody ABATTA derrière la station OLA ENERGY / N°RCCM : CI-ABJ-2017-A-25092 / NCC : 1746141.B</b><br/>"
        "<b>Compte bancaire : Orabank N° : 033201001901 / Bdu N° : 20401160186 / Cel : + 225 2722204498 / 07 09 50 02 43 / 07 47 68 20 27</b><br/>"
        "<b>Email: dg@ramyaci.tech - admin@ramyaci.tech - www.ramyatechnologie.com</b>",
        ParagraphStyle('ft', fontSize=7, alignment=TA_CENTER, textColor=TEAL, leading=10)
    ))
    
    doc.build(story)
    return output_path
