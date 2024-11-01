import subprocess
import time
import json

# JSON-Datei laden
with open('config.json') as config_file:
    config = json.load(config_file)

SIP_USERNAME = config['SIP_USERNAME']
SIP_PASSWORD = config['SIP_PASSWORD']
SIP_HOST = config['SIP_HOST']

# Funktion zur Text-to-Speech-Umwandlung
def text_to_speech(text):
    # Geschwindigkeit auf 120 Wörter pro Minute einstellen und Ausgabe in eine WAV-Datei speichern
    subprocess.run(['espeak', text, '--stdout', '-s', '120'], stdout=open('output.wav', 'wb'))

# Funktion zum Tätigen eines Anrufs
def make_call(sip_address, text):
    # Text-to-Speech in eine Datei speichern
    text_to_speech(text)
    
    # Linphone-Anruf über die Kommandozeile starten
    subprocess.run(['linphonecsh', 'init'])
    time.sleep(2)  # Kurze Pause einlegen
    subprocess.run(['linphonecsh', 'register', '--username', SIP_USERNAME, '--host', SIP_HOST, '--password', SIP_PASSWORD])
    time.sleep(2)  # Kurze Pause einlegen
    # Linphone so konfigurieren, dass es WAV-Dateien verwendet
    subprocess.run(['linphonecsh', 'soundcard', 'use', 'files'])
    time.sleep(2)  # Kurze Pause einlegen
    subprocess.run(['linphonecsh', 'dial', sip_address])
    
    # Warte, bis der Anruf verbunden ist
    time.sleep(10)  # Wartezeit anpassen je nach Bedarf
    
    # Text-to-Speech-Datei abspielen
    subprocess.run(['linphonecsh', 'generic', 'play /home/wazuhserver/output.wav'])

    time.sleep(10)  # Wartezeit anpassen je nach Bedarf
    
    # Anruf beenden
    subprocess.run(['linphonecsh', 'exit'])

# Beispielaufruf
make_call("sip:+nummber@192.168.178.1", "Hello this is a test")