import sys
import imaplib
import email
from email.header import decode_header
import xml.etree.ElementTree as ET
import gzip
from io import BytesIO
import zipfile
import configparser
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email(subject, body):
    sender = config['mail']['sender_email']
    recipient = config['mail']['report_email']
    message = MIMEMultipart()
    message['From'] = sender
    message['To'] = recipient
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))

    smtp_server = config['mail']['smtp_server']
    smtp_port = config['mail']['smtp_port']
    smtp_username = config['mail']['smtp_username']
    smtp_password = config['mail']['smtp_password']

    smtp = smtplib.SMTP(smtp_server, smtp_port)
    smtp.starttls()
    smtp.login(smtp_username, smtp_password)
    smtp.sendmail(sender, [recipient], message.as_string())
    smtp.quit()


def check_dmarc_failures(contents, subject):
    tree = ET.fromstring(contents)

    for record in tree.iter("record"):
        row = record.find("row")
        policy_evaluated = row.find("policy_evaluated")
        if policy_evaluated is not None:
            disposition = policy_evaluated.find("disposition")
            if disposition is not None:
                disposition = disposition.text.lower()
                if disposition in ("reject", "quarantine"):
                    report_metadata = tree.find('report_metadata/org_name').text
                    spf = policy_evaluated.find('spf').text
                    dkim = policy_evaluated.find('dkim').text
                    source_ip = row.find('source_ip').text
                    count = row.find('count').text
                    print(f"{subject}\n {report_metadata}, disposition: {disposition}, spf: {spf}, dkim: {dkim}, source_ip: {source_ip}, count: {count}")
                    send_email(
                        "dmarc fail detected",
                        f"{subject}\n {report_metadata}, disposition: {disposition}, spf: {spf}, dkim: {dkim}, source_ip: {source_ip}, count: {count}"
                    )

def extract_zip_xml(zip_file):
    with zipfile.ZipFile(zip_file) as z:
        for f in z.namelist():
            if f.endswith('.xml'):
                with z.open(f) as xml_file:
                    return xml_file.read().decode('utf-8')
    return None


def extract_gzip_xml(gzip_file):
    with gzip.GzipFile(fileobj=gzip_file) as gz:
        return gz.read().decode('utf-8')


# Read configuration file
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), 'config.ini'))

server = config['mail']['server']
username = config['mail']['username']
password = config['mail']['password']
sender = config['mail']['sender_email']
recipient = config['mail']['report_email']

# Connect to the server
imap = imaplib.IMAP4_SSL(server)

# Login
imap.login(username, password)

# Select the mailbox
imap.select('INBOX')

# Set search criteria
criteria = '(ALL)'

# Search for messages that match the criteria
_, uids = imap.search(None, criteria)

# Loop through each message UID
for uid in uids[0].split():
    # Fetch the message
    _, msg_data = imap.fetch(uid, '(RFC822)')
    msg = email.message_from_bytes(msg_data[0][1])
    date = msg['Date']
    subject = decode_header(msg['Subject'])[0][0]

    if isinstance(subject, bytes):
        # if it's a bytes type, decode to str
        subject = subject.decode()

    # Loop through each message part
    for part in msg.walk():
        # Check if the part is an attachment
        filename = part.get_filename()
        if not filename:
            continue

        # Check if the attachment is a ZIP or GZIP file
        if not (filename.lower().endswith('.zip') or filename.lower().endswith('.gz')):
            continue

        # Read the attachment body
        body = part.get_payload(decode=True)
        body_io = BytesIO(body)

        # Extract the contents of the attachment
        if filename.lower().endswith('.zip'):
            contents = extract_zip_xml(body_io)
        else:
            contents = extract_gzip_xml(body_io)

        # Check for DMARC failures
        if contents:
            check_dmarc_failures(contents, subject)

        # Move the message to another folder
        imap.create('Processed')  # Create the destination folder if it doesn't exist
        imap.select('Processed')
        imap.append('Processed', '\\Seen', None, msg_data[0][1])  # Append the message to the destination folder

        # Mark the original message as deleted
        imap.select('INBOX')
        imap.store(uid, '+FLAGS', '\\Deleted')

# Logout
imap.expunge()
imap.close()
imap.logout()
