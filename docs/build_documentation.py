"""Rebuild the project PDF from its editable Markdown source."""
from pathlib import Path
from html import escape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
ROOT=Path(__file__).resolve().parent
styles=getSampleStyleSheet()
styles.add(ParagraphStyle('BodyProject',fontName='Helvetica',fontSize=10.5,leading=16,spaceAfter=13,textColor=colors.HexColor('#26352e')))
styles['Heading1'].textColor=colors.HexColor('#173d2b')
styles['Heading1'].spaceAfter=20
story=[]
for block in (ROOT/'VibeShield_Project_Documentation.md').read_text().split('\n\n'):
    block=block.strip()
    if not block: continue
    if block.startswith('# '):
        lines=block.splitlines();story += [Spacer(1,100),Paragraph(escape(lines[0][2:]),styles['Title']),Spacer(1,20)]
        if len(lines)>1: story.append(Paragraph(escape(' '.join(lines[1:])),styles['BodyProject']))
    elif block.startswith('## '):
        lines=block.splitlines();story += [PageBreak(),Paragraph(escape(lines[0][3:]),styles['Heading1'])]
        if len(lines)>1: story.append(Paragraph(escape(' '.join(lines[1:])),styles['BodyProject']))
    else: story.append(Paragraph(escape(block).replace('\n','<br/>'),styles['BodyProject']))
def footer(canvas,doc):
    canvas.setFont('Helvetica',8);canvas.setFillColor(colors.HexColor('#526257'))
    canvas.drawString(45,28,'VibeShield / Academic capstone documentation')
    canvas.drawRightString(550,28,str(doc.page))
SimpleDocTemplate(str(ROOT/'VibeShield_Project_Documentation.pdf'),title='VibeShield Project Documentation',author='VibeShield',leftMargin=45,rightMargin=45,topMargin=48,bottomMargin=48).build(story,onFirstPage=footer,onLaterPages=footer)
print(ROOT/'VibeShield_Project_Documentation.pdf')
