#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
  PROGRAMME DE TRAITEMENT DES RAPPORTS DE POINTAGE
  Générateur de rapport enrichi (heures sup / respect horaire)
=============================================================================
  Entrée  : Fichier Excel (.xlsx) de présence
  Sortie  : PDF enrichi (portrait) avec :
            - Rapports individuels par employé
            - Rapport de présence global
            - Classement retards & absences
            - Graphique d'assiduité
=============================================================================
  Usage : python3 rapport_heures.py [chemin_du_xlsx]
=============================================================================
"""

import sys, os, re, math
import openpyxl
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak,
    KeepTogether
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing, Wedge, String, Circle, Rect
from reportlab.graphics import renderPDF
from datetime import datetime
from collections import defaultdict, OrderedDict

# ======================== COULEURS ========================
TEAL = HexColor("#1A7A6D")
DARK_TEAL = HexColor("#0D6B5E")
ORANGE = HexColor("#E8672A")
GREEN = HexColor("#008000")
RED = HexColor("#CC0000")
BLUE = HexColor("#0000CC")
LGRAY = HexColor("#F5F5F5")
MGRAY = HexColor("#DDDDDD")

# ======================== UTILITAIRES ========================

def t2m(t):
    """Convertit HH:MM en minutes."""
    if not t or str(t).strip() in ['-','nan','','None']: return 0
    s = str(t).strip().replace('\n','')
    p = s.split(':')
    try: return int(p[0])*60+int(p[1]) if len(p)==2 else 0
    except: return 0

def m2h(m):
    """Convertit minutes en HH:MM."""
    if m <= 0: return "00:00"
    return f"{int(m)//60:02d}:{int(m)%60:02d}"

def safe(s):
    """Échappe pour XML ReportLab."""
    return str(s).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')

# ======================== EXTRACTION EXCEL ========================

def extract_from_excel(xlsx_path):
    """Extrait les données depuis le fichier Excel."""
    wb = openpyxl.load_workbook(xlsx_path, data_only=True)
    ws = wb[wb.sheetnames[0]]
    
    # Détection du nom du client
    title = str(ws.cell(1,1).value or "")
    client_name = ""
    for r in range(3, min(6, ws.max_row+1)):
        svc = str(ws.cell(r, 4).value or "")
        if '>' in svc:
            client_name = svc.split('>')[-1].strip()
            break
    if not client_name:
        client_name = "ENTREPRISE"
    
    # Extraction des données par employé
    employees = OrderedDict()
    
    for r in range(3, ws.max_row + 1):
        prenom = str(ws.cell(r, 1).value or "").strip()
        nom = str(ws.cell(r, 2).value or "").strip()
        eid = str(ws.cell(r, 3).value or "").strip()
        
        if not prenom and not nom:
            continue
        
        full_name = f"{prenom} {nom}".strip()
        date_val = str(ws.cell(r, 5).value or "").strip()
        sched_start = str(ws.cell(r, 6).value or "").strip()
        sched_end = str(ws.cell(r, 7).value or "").strip()
        actual_arr = str(ws.cell(r, 8).value or "").strip()
        actual_dep = str(ws.cell(r, 9).value or "").strip()
        duration = str(ws.cell(r, 10).value or "").strip()
        
        # Nettoyer les dates datetime
        if 'datetime' in str(type(ws.cell(r, 5).value)):
            date_val = ws.cell(r, 5).value.strftime('%Y-%m-%d')
        
        # Nettoyer les heures datetime  
        for col_idx, col_name in [(6,'sched_start'),(7,'sched_end'),(8,'actual_arr'),(9,'actual_dep'),(10,'duration')]:
            val = ws.cell(r, col_idx).value
            if val and 'datetime' in str(type(val)):
                locals()[col_name] = val.strftime('%H:%M')
            elif val and 'time' in str(type(val)):
                locals()[col_name] = val.strftime('%H:%M')
        
        # Re-read after potential conversion
        sched_start = str(ws.cell(r, 6).value or "").strip()
        sched_end = str(ws.cell(r, 7).value or "").strip()
        actual_arr = str(ws.cell(r, 8).value or "").strip()
        actual_dep = str(ws.cell(r, 9).value or "").strip()
        duration = str(ws.cell(r, 10).value or "").strip()
        
        # Gérer les formats datetime
        for field in [sched_start, sched_end, actual_arr, actual_dep, duration]:
            pass  # Already strings
        
        key = (full_name, eid)
        if key not in employees:
            employees[key] = {
                'name': full_name,
                'ref': eid,
                'records': []
            }
        
        employees[key]['records'].append({
            'date': date_val[:10] if len(date_val) >= 10 else date_val,
            'sched_start': sched_start[:5] if len(sched_start) >= 5 else sched_start,
            'sched_end': sched_end[:5] if len(sched_end) >= 5 else sched_end,
            'arrival': actual_arr[:5] if len(actual_arr) >= 5 else actual_arr,
            'departure': actual_dep[:5] if len(actual_dep) >= 5 else actual_dep,
            'duration': duration[:5] if len(duration) >= 5 else duration,
        })
    
    # Trier les records par date pour chaque employé
    for key in employees:
        employees[key]['records'].sort(key=lambda x: x['date'])
    
    return list(employees.values()), client_name

# ======================== CALCULS ========================

def calc_employee_stats(emp, hp=0):
    """Calcule les statistiques complètes d'un employé. hp=heures obligatoires/jour (0=auto)."""
    records = emp['records']
    total_required = 0
    total_worked = 0
    total_overtime = 0
    total_deficit = 0
    total_late_mins = 0
    days_present = 0
    days_late = 0
    days_punctual = 0
    days_absent = 0
    days_badge_error = 0
    hm = hp * 60  # heures obligatoires en minutes
    
    enriched = []
    
    for rec in records:
        ss = t2m(rec['sched_start'])
        se = t2m(rec['sched_end'])
        aa = t2m(rec['arrival'])
        ad = t2m(rec['departure'])
        dur = t2m(rec['duration'])
        
        required = hm if hp > 0 else (se - ss if se > ss else 0)
        total_required += required
        
        schedule_str = f"({rec['sched_start']}_{rec['sched_end']})"
        
        # Déterminer l'état
        if dur == 0 or (aa == 0 and ad == 0):
            state = "Absent(e)"
            days_absent += 1
            worked = 0
            overtime = 0
            late = 0
            respect = "ABS"
        else:
            days_present += 1
            
            # === HEURES TRAVAILLÉES ===
            # Le comptage commence au début du planning, PAS avant
            # Ex: planning 7h-17h, arrivée 6h → on compte à partir de 7h
            effective_start = max(aa, ss)
            worked = ad - effective_start if ad > effective_start else 0
            total_worked += worked
            
            # Retard : arrivée après le début prévu
            if aa > ss:
                late = aa - ss
                total_late_mins += late
                days_late += 1
                state = "Retard"
            else:
                late = 0
                days_punctual += 1
                state = "Présent(e)"
            
            # === HEURES SUPPLÉMENTAIRES ===
            # Seulement le temps APRÈS la fin prévue du planning
            # Arriver tôt ne compte PAS comme heure sup
            if ad > se:
                overtime = ad - se
            else:
                overtime = 0
            total_overtime += overtime
            
            # === RESPECT HORAIRE ===
            # Si les heures travaillées >= heures obligatoires (tolérance 5 min) → OUI
            if worked >= (required - 5):
                respect = "OUI"
            else:
                deficit = required - worked
                total_deficit += deficit
                respect = f"NON (-{m2h(deficit)})"
        
        enriched.append({
            'date': rec['date'],
            'schedule': schedule_str,
            'state': state,
            'arrival': rec['arrival'],
            'departure': rec['departure'],
            'worked': m2h(worked),
            'late': m2h(late),
            'required': m2h(required),
            'respect': respect,
            'overtime': m2h(overtime),
        })
    
    # === ASSIDUITÉ (basée sur le taux de présence) ===
    presence_rate = (days_present / len(records) * 100) if len(records) > 0 else 0
    if presence_rate >= 95:
        observation = "Assidu"
    elif presence_rate >= 80:
        observation = "Moyennement assidu"
    else:
        observation = "Non assidu"
    
    stats = {
        'days_required': len(records),
        'days_present': days_present,
        'days_late': days_late,
        'days_punctual': days_punctual,
        'days_absent': days_absent,
        'days_badge_error': days_badge_error,
        'total_required': total_required,
        'total_worked': total_worked,
        'total_overtime': total_overtime,
        'total_deficit': total_deficit,
        'total_late_mins': total_late_mins,
        'presence_rate': round(presence_rate, 1),
        'observation': observation,
    }
    
    return enriched, stats

# ======================== STYLES PDF ========================

def make_styles():
    return {
        'co': ParagraphStyle('co', fontName='Helvetica-Bold', fontSize=10, textColor=TEAL, leading=12),
        'cl': ParagraphStyle('cl', fontName='Helvetica-Bold', fontSize=12, textColor=ORANGE, alignment=TA_RIGHT),
        'ti': ParagraphStyle('ti', fontName='Helvetica-Bold', fontSize=14, textColor=TEAL, alignment=TA_CENTER, spaceAfter=4),
        'st': ParagraphStyle('st', fontName='Helvetica', fontSize=9, alignment=TA_CENTER, spaceAfter=8),
        'ei': ParagraphStyle('ei', fontName='Helvetica-Bold', fontSize=9, spaceAfter=2),
        'eb': ParagraphStyle('eb', fontName='Helvetica-Bold', fontSize=9, textColor=BLUE, spaceAfter=2),
        'c': ParagraphStyle('c', fontName='Helvetica', fontSize=5.8, alignment=TA_CENTER, leading=7),
        'cb': ParagraphStyle('cb', fontName='Helvetica-Bold', fontSize=5.8, alignment=TA_CENTER, leading=7),
        'h': ParagraphStyle('h', fontName='Helvetica-Bold', fontSize=5.8, textColor=white, alignment=TA_CENTER, leading=7),
        'g': ParagraphStyle('g', fontName='Helvetica-Bold', fontSize=5.8, textColor=GREEN, alignment=TA_CENTER, leading=7),
        'r': ParagraphStyle('r', fontName='Helvetica-Bold', fontSize=5.8, textColor=RED, alignment=TA_CENTER, leading=7),
        'b': ParagraphStyle('b', fontName='Helvetica-Bold', fontSize=5.8, textColor=BLUE, alignment=TA_CENTER, leading=7),
        'sh': ParagraphStyle('sh', fontName='Helvetica-Bold', fontSize=6, textColor=white, alignment=TA_CENTER, leading=7),
        'sv': ParagraphStyle('sv', fontName='Helvetica', fontSize=6.5, alignment=TA_CENTER, leading=8),
        'ft': ParagraphStyle('ft', fontName='Helvetica', fontSize=6, alignment=TA_RIGHT, textColor=HexColor("#888")),
        # Styles pour les pages résumé
        'big_ti': ParagraphStyle('big_ti', fontName='Helvetica-Bold', fontSize=16, textColor=TEAL, alignment=TA_CENTER, spaceAfter=12),
        'med_ti': ParagraphStyle('med_ti', fontName='Helvetica-Bold', fontSize=12, textColor=TEAL, alignment=TA_LEFT, spaceAfter=6),
        'rh': ParagraphStyle('rh', fontName='Helvetica-Bold', fontSize=7, textColor=white, alignment=TA_CENTER, leading=9),
        'rv': ParagraphStyle('rv', fontName='Helvetica', fontSize=7, alignment=TA_CENTER, leading=9),
        'rvb': ParagraphStyle('rvb', fontName='Helvetica-Bold', fontSize=7, alignment=TA_CENTER, leading=9),
        'rvo': ParagraphStyle('rvo', fontName='Helvetica-Bold', fontSize=7, textColor=ORANGE, alignment=TA_CENTER, leading=9),
    }

# ======================== HEADER COMMUN ========================

def make_header(S, provider_name, provider_info, client_name, client_info=""):
    """Crée l'en-tête commun pour chaque page."""
    right_text = safe(client_name)
    if client_info:
        right_text += f"<br/><font size=6>{safe(client_info)}</font>"
    h = Table([
        [Paragraph(f"{safe(provider_name)}<br/><font size=6>{safe(provider_info)}</font>", S['co']),
         Paragraph(right_text, S['cl'])]
    ], colWidths=[110*mm, 80*mm])
    h.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'MIDDLE'),
                           ('LINEBELOW',(0,0),(-1,0),1,TEAL)]))
    return h

# ======================== PAGE 1-N : RAPPORTS INDIVIDUELS ========================

def gen_individual_pages(story, emps, all_stats, S, provider_name, provider_info, client_name, client_info, period, now):
    """Génère les pages de rapport individuel."""
    
    for idx, emp in enumerate(emps):
        if idx > 0: story.append(PageBreak())
        
        enriched, stats = all_stats[idx]
        
        story.append(make_header(S, provider_name, provider_info, client_name, client_info))
        story.append(Spacer(1, 3*mm))
        story.append(Paragraph("RAPPORT INDIVIDUEL ENRICHI", S['ti']))
        story.append(Paragraph(period, S['st']))
        story.append(Paragraph(f"Employé: {emp['name']}  |  Réf: {emp['ref']}", S['ei']))
        story.append(Spacer(1, 2*mm))
        
        # Résumé compact
        sum_hdrs = ["Jours<br/>prévus","Présent","Retard","Absent","Err.<br/>badge",
                    "","H. obligat.","H. travail.","H. retard","H. absent"]
        sum_vals = [
            f"{stats['days_required']}j", f"{stats['days_present']}j",
            f"{stats['days_late']}j", f"{stats['days_absent']}j", f"{stats['days_badge_error']}j",
            "",
            m2h(stats['total_required']), m2h(stats['total_worked']),
            m2h(stats['total_late_mins']),
            m2h(stats['days_absent'] * (stats['total_required'] // max(stats['days_required'],1)))
        ]
        sh = [Paragraph(x, S['sh']) for x in sum_hdrs]
        sv = [Paragraph(x, S['sv']) for x in sum_vals]
        sw = [17*mm,15*mm,14*mm,14*mm,13*mm, 4*mm, 18*mm,18*mm,16*mm,16*mm]
        stbl = Table([sh, sv], colWidths=sw)
        stbl.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(4,0),TEAL),('BACKGROUND',(6,0),(9,0),TEAL),
            ('GRID',(0,0),(4,-1),0.4,colors.grey),('GRID',(6,0),(9,-1),0.4,colors.grey),
            ('ALIGN',(0,0),(-1,-1),'CENTER'),('VALIGN',(0,0),(-1,-1),'MIDDLE'),
            ('TOPPADDING',(0,0),(-1,-1),1),('BOTTOMPADDING',(0,0),(-1,-1),1),
            ('LEFTPADDING',(0,0),(-1,-1),1),('RIGHTPADDING',(0,0),(-1,-1),1),
        ]))
        story.extend([stbl, Spacer(1, 3*mm)])
        
        # Tableau détail
        hdrs = ["N°","Date","Planning","État","Arrivée",
                "Départ","H.<br/>travail.","Retard",
                "H.<br/>obligat.","H.<br/>Respectée","H. sup."]
        cw = [7*mm,16*mm,18*mm,16*mm,13*mm,13*mm,14*mm,13*mm,14*mm,18*mm,14*mm]
        
        td = [[Paragraph(x, S['h']) for x in hdrs]]
        
        for i, rec in enumerate(enriched, 1):
            resp = rec['respect']
            if resp == "OUI":
                rp = Paragraph("OUI", S['g'])
            elif resp == "ABS":
                rp = Paragraph("ABS", S['r'])
            elif resp.startswith("NON"):
                rp = Paragraph(resp.replace(" ","<br/>"), S['r'])
            else:
                rp = Paragraph(resp, S['c'])
            
            ot_mins = t2m(rec['overtime'])
            ot = Paragraph(rec['overtime'], S['b']) if ot_mins > 0 else Paragraph(rec['overtime'], S['c'])
            
            td.append([
                Paragraph(str(i), S['c']),
                Paragraph(rec['date'], S['c']),
                Paragraph(rec['schedule'], S['c']),
                Paragraph(rec['state'], S['cb']),
                Paragraph(rec['arrival'], S['c']),
                Paragraph(rec['departure'], S['c']),
                Paragraph(rec['worked'], S['cb']),
                Paragraph(rec['late'], S['c']),
                Paragraph(rec['required'], S['cb']),
                rp, ot
            ])
        
        dt = Table(td, colWidths=cw, repeatRows=1)
        sc = [('BACKGROUND',(0,0),(-1,0),TEAL),('BACKGROUND',(8,0),(10,0),DARK_TEAL),
              ('GRID',(0,0),(-1,-1),0.3,colors.grey),
              ('ALIGN',(0,0),(-1,-1),'CENTER'),('VALIGN',(0,0),(-1,-1),'MIDDLE'),
              ('TOPPADDING',(0,0),(-1,-1),1),('BOTTOMPADDING',(0,0),(-1,-1),1),
              ('LEFTPADDING',(0,0),(-1,-1),1),('RIGHTPADDING',(0,0),(-1,-1),1)]
        for i in range(2, len(td), 2):
            sc.append(('BACKGROUND',(0,i),(-1,i),LGRAY))
        dt.setStyle(TableStyle(sc))
        story.append(dt)
        
        # Totaux
        story.append(Spacer(1, 2*mm))
        tt = Table([[
            Paragraph(f"<b>TOTAL H. SUPPLÉMENTAIRES : {m2h(stats['total_overtime'])}</b>",
                ParagraphStyle('x',fontName='Helvetica-Bold',fontSize=8,textColor=BLUE)),
            Paragraph(f"<b>TOTAL DÉFICIT : {m2h(stats['total_deficit'])}</b>",
                ParagraphStyle('x',fontName='Helvetica-Bold',fontSize=8,textColor=RED)),
        ]], colWidths=[95*mm,95*mm])
        tt.setStyle(TableStyle([('BOX',(0,0),(-1,-1),0.8,TEAL),
            ('INNERGRID',(0,0),(-1,-1),0.4,TEAL),
            ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
            ('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3),
            ('LEFTPADDING',(0,0),(-1,-1),4)]))
        story.extend([tt, Spacer(1,2*mm),
            Paragraph(f"Généré le {now} | {safe(client_name)} - Rapport enrichi", S['ft'])])

# ======================== PAGE : RAPPORT DE PRÉSENCE ========================

def gen_rapport_presence(story, emps, all_stats, S, provider_name, provider_info, client_name, client_info, now):
    story.append(PageBreak())
    story.append(make_header(S, provider_name, provider_info, client_name, client_info))
    story.append(Spacer(1, 6*mm))
    story.append(Paragraph("RAPPORT DE PRÉSENCE", S['big_ti']))
    story.append(Spacer(1, 4*mm))
    
    hdrs = ["N°","Employé","Jours<br/>obligat.","Jours de<br/>présence",
            "Taux<br/>présence","Jours de<br/>retards","Jours<br/>ponctuel","Jours<br/>d'absences",
            "Observation"]
    hrow = [Paragraph(h, S['rh']) for h in hdrs]
    cw = [8*mm, 30*mm, 16*mm, 16*mm, 16*mm, 16*mm, 16*mm, 16*mm, 28*mm]
    
    td = [hrow]
    for i, (emp, (enriched, stats)) in enumerate(zip(emps, all_stats), 1):
        obs = stats['observation']
        if obs == "Non assidu":
            obs_style = S['rvo']
        elif obs == "Moyennement assidu":
            obs_style = ParagraphStyle('rvblue', fontName='Helvetica-Bold', fontSize=7, textColor=BLUE, alignment=TA_CENTER, leading=9)
        else:
            obs_style = ParagraphStyle('rvgreen', fontName='Helvetica-Bold', fontSize=7, textColor=GREEN, alignment=TA_CENTER, leading=9)
        td.append([
            Paragraph(str(i), S['rv']),
            Paragraph(emp['name'], S['rvb']),
            Paragraph(f"{stats['days_required']} j", S['rv']),
            Paragraph(f"{stats['days_present']} j", S['rv']),
            Paragraph(f"{stats.get('presence_rate', 0):.0f}%", S['rv']),
            Paragraph(f"{stats['days_late']} j", S['rv']),
            Paragraph(f"{stats['days_punctual']} j", S['rv']),
            Paragraph(f"{stats['days_absent']} j", S['rv']),
            Paragraph(obs, obs_style),
        ])
    
    t = Table(td, colWidths=cw, repeatRows=1)
    sc = [('BACKGROUND',(0,0),(-1,0),TEAL),
          ('GRID',(0,0),(-1,-1),0.4,colors.grey),
          ('ALIGN',(0,0),(-1,-1),'CENTER'),('VALIGN',(0,0),(-1,-1),'MIDDLE'),
          ('TOPPADDING',(0,0),(-1,-1),2),('BOTTOMPADDING',(0,0),(-1,-1),2)]
    for i in range(2, len(td), 2):
        sc.append(('BACKGROUND',(0,i),(-1,i),LGRAY))
    t.setStyle(TableStyle(sc))
    story.extend([t, Spacer(1,4*mm),
        Paragraph(f"Généré le {now}", S['ft'])])

# ======================== PAGE : CLASSEMENT RETARDS & ABSENCES ========================

def gen_classement(story, emps, all_stats, S, provider_name, provider_info, client_name, client_info, now):
    story.append(PageBreak())
    story.append(make_header(S, provider_name, provider_info, client_name, client_info))
    story.append(Spacer(1, 6*mm))
    story.append(Paragraph("CLASSEMENT PAR DEGRÉ DE RETARDS ET D'ABSENCES", S['big_ti']))
    story.append(Spacer(1, 6*mm))
    
    # Classement par retards
    retards = [(emp['name'], stats['total_late_mins']) 
               for emp, (_, stats) in zip(emps, all_stats) if stats['total_late_mins'] > 0]
    retards.sort(key=lambda x: -x[1])
    
    story.append(Paragraph("Classement par Retards", S['med_ti']))
    hdrs = [Paragraph(h, S['rh']) for h in ["Rang","Nom Employé","Total heure de retard"]]
    td_r = [hdrs]
    for i, (name, mins) in enumerate(retards[:10], 1):
        td_r.append([Paragraph(str(i), S['rv']), Paragraph(name, S['rvb']),
                     Paragraph(m2h(mins), S['rv'])])
    
    if len(td_r) > 1:
        tr = Table(td_r, colWidths=[15*mm, 80*mm, 40*mm])
        tr.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0),TEAL),
            ('GRID',(0,0),(-1,-1),0.4,colors.grey),
            ('ALIGN',(0,0),(-1,-1),'CENTER'),('VALIGN',(0,0),(-1,-1),'MIDDLE'),
            ('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3)]))
        story.append(tr)
    
    story.append(Spacer(1, 8*mm))
    
    # Classement par absences
    absences = [(emp['name'], stats['days_absent'])
                for emp, (_, stats) in zip(emps, all_stats) if stats['days_absent'] > 0]
    absences.sort(key=lambda x: -x[1])
    
    story.append(Paragraph("Classement par Absences", S['med_ti']))
    hdrs2 = [Paragraph(h, S['rh']) for h in ["Rang","Nom Employé","Nombre de jours d'absence"]]
    td_a = [hdrs2]
    for i, (name, days) in enumerate(absences[:10], 1):
        td_a.append([Paragraph(str(i), S['rv']), Paragraph(name, S['rvb']),
                     Paragraph(str(days), S['rv'])])
    
    if len(td_a) > 1:
        ta = Table(td_a, colWidths=[15*mm, 80*mm, 45*mm])
        ta.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0),TEAL),
            ('GRID',(0,0),(-1,-1),0.4,colors.grey),
            ('ALIGN',(0,0),(-1,-1),'CENTER'),('VALIGN',(0,0),(-1,-1),'MIDDLE'),
            ('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3)]))
        story.append(ta)
    
    story.extend([Spacer(1,4*mm), Paragraph(f"Généré le {now}", S['ft'])])

# ======================== PRÉPARATION LOGO ========================

def _prepare_logo(logo_path, work_dir=None):
    """Supprime le fond noir du logo et retourne le chemin du logo nettoyé."""
    try:
        from PIL import Image
        import numpy as np
        
        img = Image.open(logo_path).convert('RGBA')
        data = np.array(img)
        
        dark = (data[:,:,0] < 45) & (data[:,:,1] < 45) & (data[:,:,2] < 45)
        data[dark, 3] = 0
        
        img_clean = Image.fromarray(data)
        bbox = img_clean.getbbox()
        if bbox:
            img_clean = img_clean.crop(bbox)
        
        w, h = img_clean.size
        size = max(w, h)
        square = Image.new('RGBA', (size, size), (255, 255, 255, 0))
        square.paste(img_clean, ((size - w) // 2, (size - h) // 2), img_clean)
        
        out_dir = work_dir or os.path.dirname(os.path.abspath(logo_path))
        clean_path = os.path.join(out_dir, 'logo_clean.png')
        square.save(clean_path)
        
        return clean_path
    except Exception as e:
        print(f"  ⚠️  Erreur traitement logo: {e}")
        return None


def _generate_chart_image(pct_presence, pct_absence, logo_path=None, work_dir=None):
    """Génère un graphique donut 3D avec légende et logo au centre."""
    try:
        from PIL import Image, ImageDraw, ImageFont
        
        W, H = 1000, 700
        cx, cy = 350, 320
        outer_r = 260
        inner_r = 130
        depth = 30  # Profondeur 3D
        
        img = Image.new('RGBA', (W, H), (255, 255, 255, 255))
        draw = ImageDraw.Draw(img)
        
        # Couleurs
        teal = (26, 122, 109, 255)
        teal_dark = (18, 90, 80, 255)
        red = (232, 93, 74, 255)
        red_dark = (180, 65, 50, 255)
        green_c = (46, 125, 50, 255)
        orange_c = (232, 103, 42, 255)
        blue_c = (26, 58, 92, 255)
        
        # === 3D DEPTH (ombres dessous) ===
        for d in range(depth, 0, -1):
            shade = int(200 - d * 3)
            draw.ellipse([cx-outer_r, cy-outer_r+d, cx+outer_r, cy+outer_r+d],
                        fill=(shade, shade, shade, 80))
        
        # Disque 3D inférieur (ombre du donut)
        for d in range(depth, 0, -1):
            draw.ellipse([cx-outer_r, cy-outer_r+d, cx+outer_r, cy+outer_r+d], fill=teal_dark)
            if pct_absence > 0:
                a_start = -90
                a_end = -90 + (360 * pct_absence / 100)
                draw.pieslice([cx-outer_r, cy-outer_r+d, cx+outer_r, cy+outer_r+d],
                             start=a_start, end=a_end, fill=red_dark)
        
        # Disque principal (dessus)
        draw.ellipse([cx-outer_r, cy-outer_r, cx+outer_r, cy+outer_r], fill=teal)
        if pct_absence > 0:
            a_start = -90
            a_end = -90 + (360 * pct_absence / 100)
            draw.pieslice([cx-outer_r, cy-outer_r, cx+outer_r, cy+outer_r],
                         start=a_start, end=a_end, fill=red)
        
        # Reflet lumineux (effet 3D)
        for i in range(20):
            alpha = int(40 - i * 2)
            draw.ellipse([cx-outer_r+i+30, cy-outer_r+i+20, cx-30, cy-30],
                        fill=(255, 255, 255, alpha))
        
        # Trou central
        if logo_path and os.path.exists(logo_path):
            clean_path = _prepare_logo(logo_path, work_dir)
            if clean_path:
                logo = Image.open(clean_path).convert('RGBA')
                logo_size = inner_r * 2 + 10
                logo = logo.resize((logo_size, logo_size), Image.LANCZOS)
                lx, ly = cx - logo_size // 2, cy - logo_size // 2
                img.paste(logo, (lx, ly), logo)
            else:
                draw.ellipse([cx-inner_r, cy-inner_r, cx+inner_r, cy+inner_r], fill=(255,255,255,255))
        else:
            draw.ellipse([cx-inner_r, cy-inner_r, cx+inner_r, cy+inner_r], fill=(255,255,255,255))
            try: font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 42)
            except: font = ImageFont.load_default()
            text = f"{pct_presence:.1f}%"
            bbox = draw.textbbox((0, 0), text, font=font)
            tw = bbox[2] - bbox[0]
            th = bbox[3] - bbox[1]
            draw.text((cx - tw//2, cy - th//2), text, fill=teal, font=font)
        
        # === LÉGENDE (à droite) ===
        try:
            font_leg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 22)
            font_leg_b = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 24)
            font_title = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 20)
            font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 16)
        except:
            font_leg = font_leg_b = font_title = font_small = ImageFont.load_default()
        
        lx_start = 660
        ly = 80
        
        draw.text((lx_start, ly), "Légende", fill=blue_c, font=font_title)
        ly += 45
        
        # Présence
        draw.rounded_rectangle([lx_start, ly, lx_start+28, ly+28], radius=4, fill=teal)
        draw.text((lx_start+36, ly), f"Présence: {pct_presence:.1f}%", fill=(60,60,60), font=font_leg_b)
        ly += 45
        
        # Absence
        draw.rounded_rectangle([lx_start, ly, lx_start+28, ly+28], radius=4, fill=red)
        draw.text((lx_start+36, ly), f"Absence: {pct_absence:.1f}%", fill=(60,60,60), font=font_leg_b)
        ly += 60
        
        # Abréviations
        draw.text((lx_start, ly), "Abréviations", fill=blue_c, font=font_title)
        ly += 35
        abbrevs = [
            ("H. travail.", "Heures travaillées"),
            ("H. obligat.", "Heures obligatoires"),
            ("H. Respectée", "Heures respectées (OUI/NON)"),
            ("H. sup.", "Heures supplémentaires"),
            ("ABS", "Absent"),
            ("P", "Présent"),
            ("R", "Retard"),
        ]
        for abbr, full in abbrevs:
            draw.text((lx_start, ly), f"{abbr}", fill=orange_c, font=font_small)
            draw.text((lx_start + 130, ly), f"= {full}", fill=(100,100,100), font=font_small)
            ly += 28
        
        # Assiduité rules
        ly += 15
        draw.text((lx_start, ly), "Règles d'assiduité", fill=blue_c, font=font_title)
        ly += 32
        rules = [("≥ 95%", "Assidu", green_c), ("80-95%", "Moy. assidu", orange_c), ("< 80%", "Non assidu", red)]
        for pct_label, label, color in rules:
            draw.rounded_rectangle([lx_start, ly, lx_start+12, ly+12], radius=2, fill=color)
            draw.text((lx_start+20, ly-4), f"{pct_label} → {label}", fill=(80,80,80), font=font_small)
            ly += 28
        
        # Convert to RGB
        final = Image.new('RGB', (W, H), (255, 255, 255))
        final.paste(img, mask=img.split()[3])
        
        out_dir = work_dir or os.path.dirname(os.path.abspath(logo_path)) if logo_path else '/tmp'
        chart_path = os.path.join(out_dir, '_chart_donut.png')
        final.save(chart_path, 'PNG', quality=95)
        return chart_path
        
    except Exception as e:
        print(f"  ⚠️  Erreur génération graphique: {e}")
        return None

# ======================== PAGE : GRAPHIQUE D'ASSIDUITÉ ========================

def gen_graphique(story, emps, all_stats, S, provider_name, provider_info, client_name, client_info, now, logo_path=None, work_dir=None):
    story.append(PageBreak())
    story.append(make_header(S, provider_name, provider_info, client_name, client_info))
    story.append(Spacer(1, 6*mm))
    story.append(Paragraph("GRAPHIQUE D'ASSIDUITÉ DU MOIS", S['big_ti']))
    story.append(Spacer(1, 8*mm))
    
    # Calculs globaux
    total_presence = sum(s['total_worked'] for _, s in all_stats)
    total_required = sum(s['total_required'] for _, s in all_stats)
    total_absence = max(0, total_required - total_presence)
    
    if total_required > 0:
        pct_presence = (total_presence / total_required) * 100
        pct_absence = 100 - pct_presence
    else:
        pct_presence = 100
        pct_absence = 0
    
    # Générer le graphique en image PIL pour gérer la transparence du logo
    chart_path = _generate_chart_image(pct_presence, pct_absence, logo_path, work_dir)
    
    if chart_path:
        from reportlab.platypus import Image as PLImage
        img = PLImage(chart_path, width=140*mm, height=140*mm)
        story.append(img)
    
    story.append(Spacer(1, 4*mm))
    
    # Légendes texte
    story.append(Paragraph(
        f"<font color='#E85D4A'><b>Absence ({m2h(total_absence)} - {pct_absence:.0f}%)</b></font>",
        ParagraphStyle('la', fontSize=10, alignment=TA_RIGHT, spaceAfter=2)))
    story.append(Paragraph(
        f"<font color='#1A7A6D'><b>Présence ({m2h(total_presence)} - {pct_presence:.0f}%)</b></font>",
        ParagraphStyle('lp', fontSize=10, alignment=TA_LEFT, spaceAfter=6)))
    
    story.append(Spacer(1, 4*mm))
    
    # Légende en bas
    leg = Table([[
        Paragraph(f"<font color='#1A7A6D'><b>■</b></font>  Total heure de présence: {m2h(total_presence)}", 
                  ParagraphStyle('l1', fontSize=9)),
        Paragraph(f"<font color='#E85D4A'><b>■</b></font>  <font color='#E85D4A'>Total heure d'absence: {m2h(total_absence)}</font>",
                  ParagraphStyle('l2', fontSize=9)),
    ]], colWidths=[95*mm, 95*mm])
    leg.setStyle(TableStyle([('BOX',(0,0),(-1,-1),0.5,colors.grey),
        ('INNERGRID',(0,0),(-1,-1),0.5,colors.grey),
        ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
        ('LEFTPADDING',(0,0),(-1,-1),6)]))
    story.extend([leg, Spacer(1,4*mm), Paragraph(f"Généré le {now}", S['ft'])])

# ======================== GENERATION PDF COMPLETE ========================

def generate_full_pdf(emps, output_path, provider_name, provider_info, client_name, period, logo_path=None, hp=0, client_info="", work_dir=None):
    if not work_dir:
        work_dir = os.path.dirname(os.path.abspath(output_path))
    doc = SimpleDocTemplate(output_path, pagesize=A4,
        leftMargin=6*mm, rightMargin=6*mm, topMargin=6*mm, bottomMargin=6*mm)
    S = make_styles()
    story = []
    now = datetime.now().strftime("%d/%m/%Y à %H:%M")
    
    # Pré-calculer toutes les stats
    all_stats = [calc_employee_stats(emp, hp) for emp in emps]
    
    # 1. Rapports individuels
    gen_individual_pages(story, emps, all_stats, S, provider_name, provider_info, client_name, client_info, period, now)
    
    # 2. Rapport de présence
    gen_rapport_presence(story, emps, all_stats, S, provider_name, provider_info, client_name, client_info, now)
    
    # 3. Classement retards & absences
    gen_classement(story, emps, all_stats, S, provider_name, provider_info, client_name, client_info, now)
    
    # 4. Graphique d'assiduité
    gen_graphique(story, emps, all_stats, S, provider_name, provider_info, client_name, client_info, now, logo_path, work_dir)
    
    doc.build(story)

# ======================== MAIN ========================

def main():
    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║   Générateur de Rapport de Pointage Enrichi               ║")
    print("║   (heures sup / respect horaire / classement / graphique) ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")
    
    # ---- 1. Fichier Excel ----
    file_path = (sys.argv[1] if len(sys.argv)>1 
                 else input("📄 Fichier Excel (.xlsx) — glissez-déposez : ").strip().strip('"').strip("'"))
    
    if not os.path.exists(file_path):
        print(f"\n❌ Fichier '{file_path}' introuvable."); sys.exit(1)
    print(f"  ✅ {os.path.basename(file_path)}")
    
    # ---- 2. Extraction ----
    print(f"\n  🔄 Extraction des données...")
    emps, detected_client = extract_from_excel(file_path)
    
    if not emps:
        print("\n  ❌ Aucun employé trouvé."); sys.exit(1)
    
    print(f"  ✅ {len(emps)} employé(s) détecté(s)")
    
    # ---- 3. Noms des entreprises ----
    print(f"\n  🏢 VOTRE SOCIÉTÉ (Entrée = RAMYA TECHNOLOGIE & INNOVATION) :")
    new_prov = input("     → ").strip()
    provider_name = new_prov if new_prov else "RAMYA TECHNOLOGIE & INNOVATION"
    
    if new_prov:
        new_info = input("     Tél & Email : ").strip()
        provider_info = new_info if new_info else "Tél: 2722204498 | Email: techniqueramya@gmail.com"
    else:
        provider_info = "Tél: 2722204498 | Email: techniqueramya@gmail.com"
    
    print(f"\n  🏬 ENTREPRISE CLIENTE (Entrée = {detected_client}) :")
    new_client = input("     → ").strip()
    client_name = new_client if new_client else detected_client
    
    # ---- 4. Période ----
    # Détecter depuis les dates des enregistrements
    all_dates = []
    for emp in emps:
        for rec in emp['records']:
            all_dates.append(rec['date'])
    if all_dates:
        all_dates.sort()
        period = f"Période du {all_dates[0]} au {all_dates[-1]}"
    else:
        period = "Rapport de pointage"
    
    print(f"\n  📅 {period}")
    
    # ---- 5. Logo ----
    # Chercher le logo dans le même dossier que le fichier Excel, ou le dossier du script
    logo_path = None
    search_dirs = [os.path.dirname(os.path.abspath(file_path)), os.getcwd(), 
                   os.path.dirname(os.path.abspath(__file__))]
    logo_names = ['logo_ramya_ROIND.png', 'logo_ramya.png', 'logo.png']
    for d in search_dirs:
        for ln in logo_names:
            candidate = os.path.join(d, ln)
            if os.path.exists(candidate):
                logo_path = candidate
                break
        if logo_path:
            break
    
    if logo_path:
        print(f"  🖼️  Logo trouvé : {os.path.basename(logo_path)}")
    else:
        print(f"  ℹ️  Pas de logo trouvé (placez logo_ramya_ROIND.png dans le même dossier)")
    
    # ---- 6. Liste des employés ----
    print(f"\n  👥 Employés :")
    for i, emp in enumerate(emps, 1):
        print(f"     {i:2d}. {emp['name']:<25s} ({emp['ref']}) → {len(emp['records'])} jours")
    
    # ---- 6. Génération ----
    base = os.path.splitext(os.path.basename(file_path))[0]
    out_dir = os.path.dirname(os.path.abspath(file_path))
    out = os.path.join(out_dir, f"{base}_RAPPORT_COMPLET.pdf")
    try:
        with open(out, 'wb') as f: pass
        os.remove(out)
    except OSError:
        out = os.path.join(os.getcwd(), f"{base}_RAPPORT_COMPLET.pdf")
    
    print(f"\n  🔄 Génération du PDF complet...")
    generate_full_pdf(emps, out, provider_name, provider_info, client_name, period, logo_path)
    
    print(f"\n  ✅ SUCCÈS → {out}")
    print(f"     🏢 {provider_name} → {client_name}")
    print(f"     👥 {len(emps)} employés")
    print(f"     📄 Contenu : Rapports individuels + Présence + Classement + Graphique\n")
    return out

if __name__ == "__main__":
    main()
