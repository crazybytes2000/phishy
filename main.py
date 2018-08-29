import subprocess, os, sys, yara
from functionalitati.parsaremail import *
from functionalitati.altefunctii import * 
from functionalitati.yaramatch import yara_match
from functionalitati.spamassassin import spamassassin

email_sample = sys.argv[1]

yararules_email = yara.compile ( filepath = "/home/bits/Desktop/licenta/yara_rules/rules-master/email_index.yar" ) # va interpreta toate regulile yara din directoriul rules-master/email ; in caz ca sunt adaugate noi reguli, calea trebuie sa se modifice compiland toate fisierele sau pe rand.

create_report(email_sample) # creem direcoriul cu sinteza analizei

sinteza_raport = open("/home/bits/Desktop/licenta/reports/" + email_sample + "/sinteza_raport","w")

header = decode_header(email_sample) 

sinteza_raport.write("Analiza email \n\n\n\n1. Detalii din headerul email-ului:\n\nSender name: " +str(header['sender_name']) + "\nSender email address: "+ str(header['sender_email_address']) + '\nEmail subject: ' + str(header['subject']) + "\nData la care a fost transmis: " + str(header['Date']) + "\nMessage-ID: " + str(header['Message-ID']) + "\nAutentificarea cu SPF: " + str(header["Received-SPF"]) + "\nAutentificarea cu semnatura DKIM: " + str(header["DKIM-Signature"]) + "\nRezultate despre autentificarea cu DMARC: " + str(header["Authentication-Results"]) + "\nReceived from: ") 

if header["Servers_paths"] is not None:
    for index in range(len(header["Servers_paths"])):
        header["Servers_paths"][index] = "\n" + header["Servers_paths"][index]
        header["Servers_paths"][index] = header["Servers_paths"][index].replace("\n","\n\t\t\t")
        sinteza_raport.write(header["Servers_paths"][index] + "\n")
else:
    sinteza_raport.write(str(header["Servers_paths"]))

body = decode_body(email_sample)
attachments_md5 = file_hash(email_sample) #va returna un dictionar de forma { numefisier : MD5 }, as in caz ca sunt fisiere in pathul de atasamente

if "body" in body:
    if isinstance(body["body"],bytes):    #in unele cazuri body-ul returnat e de tip bytes in loc de string.
        body["body"] = body["body"].decode("utf-8")
    sinteza_raport.write("\n\n2. Detalii din body-ul mailului:\n\nMesajulul din body-ul mailului a fost trimis in text/plain:\n\t\t\t" + body["body"])
if "part_1" in body:
    sinteza_raport.write("\n\n2. Detalii din body-ul mailului:\n\nMesajulul din body-ul mailului a fost trimis in text/html in loc de tect/plain:\n\t\t\t" + body["part_1"])
if "part_2" in body:
    sinteza_raport.write("\n\n2. Detalii din body-ul mailului:\n\nMesajulul din body-ul mailului a fost trimis in text/html in loc de tect/plain:\n\t\t\t" + body["part_2"])
if "body" in body and "part_1" in body:
    sinteza_raport.write("\n\n2. Detalii din body-ul mailului:\n\nMesajulul din body-ul mailului a fost trimis in text/html si text/plain. Partea de text/plain contine urmatoarele:\n\t\t\t" +  body["body"] + "\n\n Partea de text/html contine urmatoarele:\n\t\t\t" + body["part_1"] )

if len(attachments_md5) != 0:
    sinteza_raport.write("\nEmailul a fost trimis continand urmatoarele atasamente, datele urmatoare avand modelul NUME_FISIER : MD5")
    for nume,md5 in attachments_md5.items():
        sinteza_raport.write("\n\t\t\t" + nume + " : " + md5)
else:
    sinteza_raport.write("\nEmailul nu contine vreun atasament")

urls_from_mail = extract_urls_from_mail(body) #extragem URL-urile din mail

if len(urls_from_mail) != 0 :
    sinteza_raport.write("\n\nUrmatoarele URL-uri au fost adaugate in body-ul email-ului de catre sender:")
    for url in urls_from_mail:
        sinteza_raport.write("\n\t\t\t" + url)
else:
    sinteza_raport.write("\n\nNu au fost gasite URL-uri adaugate in body-ul email-ului")

## se vor scrie detalii despre analiza bazata pe reguli yara si spamassassin 
yararules_result = yara_match( "/home/bits/Desktop/licenta/samples/" + email_sample , yararules_email )
spamassassin = spamassassin( email_sample)

sinteza_raport.write("\n\n\n3.Detalii suplimentare despre email folosind spamassassin si reguli yara\n")
if len(yararules_result) != 0:
    sinteza_raport.write("\nRezultat privind analiza cu reguli yara, pentru detalii suplimentare, verificati directoriul cu reguli yara '/home/bits/licenta/yara_rules'. Emailul contine urmatorii indicatori:")
    for rule in yararules_result:
        sinteza_raport.write("\n\t\t\t" + str(rule))
else:
    sinteza_raport.write("\nNicio regula YARA nu a facut matching pe email.")

sinteza_raport.write("\n\nDetalii despre analiza cu 'spamassassin:'")
if spamassassin == "SPAM":
    sinteza_raport.write("\nEmailul este catalogat ca SPAM de spamassassin. Pentru mai multe detalii consultati raportul spamassassin din directoriul ~/licenta/reports/" + email_sample + "/spamassassin_report")
elif spamassassin == "NOT-SPAM":
    sinteza_raport.write("\nEmailul este catalogat ca NOT-SPAM de spamassassin. Pentru mai multe detalii consultati raportul spamassassin din directoriul ~/licenta/reports/" + email_sample + "/spamassassin_report.")
elif spamassassin == "ERROR":
    sinteza_raport.write("\nNu s-a putut folosi spamassassin pe mail din cauza unei errori.. Pentru mai multe detalii consultati detaliile despre eroare de la spamassassin din directoriul ~/licenta/reports/" + email_sample + "/spamassassin_error")







sinteza_raport.close()
