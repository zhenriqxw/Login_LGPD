import smtplib
from email.mime.text import MIMEText
from config import EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASS

def env_email(destinatario, assunto, mensagem):
    msg = MIMEText(mensagem)
    msg["Subject"] = assunto
    msg["From"] = EMAIL_USER
    msg["To"] = destinatario

    try:
        servidor = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        servidor.starttls()
        servidor.login(EMAIL_USER, EMAIL_PASS)
        servidor.sendmail(EMAIL_USER, destinatario, msg.as_string())
        servidor.quit()
        return True
    except Exception as e:
        print("Erro ao enviar e-mail:", e)
        return False
