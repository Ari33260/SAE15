import numpy as np
import os
    
    
try:
    #with open("evenementSAE_15.ics", encoding="utf8") as fh:
    with open("wireshark.txt", encoding="utf8") as fh:
        res=fh.read()
except:
    print("Le fichier n'existe pas %s", os.path.abspath("wireshark.txt"))
    
tamere = open("myfile.csv", "w")
#res=tools_sae.lecture_fichier("ADE_Cal.ics")
ress=res.split('\n')
#comptage=ress.count('BEGIN:VEVENT')
tableau_evenements=np.array([])
SYN ="[S],"
POUSSER = "[P.],"
RST = "[R],"
resultat=[]
ip={}
for event in ress:
    # Initialisation chaine de carcatere
    if event.startswith('11:42'):
        texte=event.split(" ")
        if texte[5] == "Flags":
            evenement='temps : '+texte[0]+' Adresse Ip source : '+texte[2]+' Adresse IP destinataire : '+texte[4]+' flag : '+texte[6]
            if texte[6] == SYN:
                evenement_3 = ' '
                evenement_2 = 'Numéro de séquence : '+texte[8]+' Taille de la fenêtre : '+texte[10]+' Longueur du paquet : '+texte[12]
            if texte[6] == POUSSER:
                evenement_3 = ' '
                evenement_2 = 'Numéro de séquence : '+texte[8]+' Numéro accusé de réception : '+texte[10]
            if texte[6] == "[.],":
                evenement_2 = 'Numéro accusé de réception : '+texte[8]+' Taille de la fenêtre : '+texte[10]
                evenement_3 = ' Longueur du paquet : '+texte[12]
            if texte[6] == "[S.],":
                evenement_2 = 'Numéro de séquence : '+texte[8]+' Numéro accusé de réception : '+texte[10]+' Taille de la fenêtre : '+texte[12]
        #print(evenement+evenement_2+evenement_3)
        #print("\n")
        strevenement= ";".join(texte)+"\n"
        resultat.append(strevenement)
        ipv4=texte[2].split(".")
        if len(ipv4)>1:
            del ipv4[-1]
            stripv4 = ".".join(ipv4)
        else:
            stripv4=ipv4[0]
        try:
            ip[stripv4]
        except KeyError:
            ip[stripv4]=1
        else:
            ip[stripv4]+=1
for key in ip.keys():
    print(key)
    
            
with open('myfile.csv','w',newline='') as fhcsv:
    for i in resultat:    
        fhcsv.write(i)

#print(sorted(ip.items(), key=lambda item: item[1]))
csv = sorted(ip.items(), key=lambda item: item[1])
print(csv)
             
fhcsv.close()
fh.close()
