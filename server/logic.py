import os
from dotenv import load_dotenv
from flask import send_file
import smtplib
from email.mime.text import MIMEText

def send_email(to_address, subject, body):
    msg = MIMEText(body, "html")
    msg['Subject'] = subject
    msg['From'] = os.getenv('EMAIL')
    msg['To'] = to_address

    with smtplib.SMTP("smtp.zoho.com", 587) as server:
        server.login(os.getenv('EMAIL'), os.getenv('EMAIL_PASSWORD'))
        server.sendmail(msg['From'], msg['To'], msg)
