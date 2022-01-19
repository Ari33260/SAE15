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
            evenement=texte[0]+';'+texte[2]+';'+texte[4]+';'+texte[6]
            if texte[6] == "[S],":
                evenement=evenement+';'+texte[8]
            if texte[6] == "[P.],":
                evenment=evenement+';'+texte[8]+';'+texte[10]
            if texte[6] == "[.],":
                evenement=evenement+';'+texte[8]
            if texte[6] == "[S.],":
                evenement=evenement+';'+texte[8]+';'+texte[10]
        else:
            evenement=texte[0]+';'+texte[2]+';'+texte[4]+';'

            
            
            
        #print(evenement+evenement_2+evenement_3)
        #print("\n")
        #strevenement= ";".join(evenement+evenement_2+evenement_3)+"\n"
        print(evenement+'\n')
        resultat.append(evenement+'\n')
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
    fhcsv.write('temps;Adresse IP Source;Adresse IP Destinataire;Flag;Numéro de séquence;Numéro accusé de réception;Taille du paquet;\n')
    for i in resultat:    
        fhcsv.write(i)

#print(sorted(ip.items(), key=lambda item: item[1]))
csv = sorted(ip.items(), key=lambda item: item[1])
print(csv)
             
fhcsv.close()
fh.close()
