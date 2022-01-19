import numpy as np
import datetime

try:
    #with open("evenementSAE_15.ics", encoding="utf8") as fh:
    with open("wireshark.txt", encoding="utf8") as fh:
        res=fh.read()
except:
    print("Le fichier n'existe pas %s",)
#res=tools_sae.lecture_fichier("ADE_Cal.ics")
ress=res.split('\n')
#comptage=ress.count('BEGIN:VEVENT')
tableau_evenements=np.array([])
SYN ="[S],"
POUSSER = "[P.],"
RST = "[R],"
print(ress[5])
print("\n")
for event in ress:
    # Initialisation chaine de carcatere
    if event.startswith('11:42'):
        texte=event.split(" ")
        if texte[5] == "Flags":
            evenement='temps : '+texte[0]+' Adresse Ip source : '+texte[2]+' Adresse IP destinataire : '+texte[4]+' flag : '+texte[6]
            if texte[6] == SYN:
                evenement_2 = 'Numéro de séquence : '+texte[8]+' Taille de la fenêtre : '+texte[10]+' Longueur du paquet : '+texte[12]
            if texte[6] == POUSSER:
                evenement_2 = 'Numéro de séquence : '+texte[8]+' Numéro accusé de réception : '+texte[10]
            if texte[6] == "[.],":
                evenement_2 = 'Numéro accusé de réception : '+texte[8]+' Taille de la fenêtre : '+texte[10]+' Longueur du paquet : '+texte[18]
            if texte[6] == "[S.],":
                evenement_2 = 'Numéro de séquence : '+texte[8]+' Numéro accusé de réception : '+texte[10]+' Taille de la fenêtre : '+texte[12]+' Longueur du paquet : '+texte[22]
            print(evenement,evenement_2)
            print("\n")
    