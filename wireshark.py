import os
    
file = input("Merci de rentrer le PWD de votre fichier TCP Dump : \n")
try:
    with open(file, encoding="utf8") as fh:
        res=fh.read()
except:
    print("Le fichier n'existe pas %s", os.path.abspath("wireshark.txt"))
ress=res.split('\n')
resultat=[]
ip={}
depart = input("Quel est le départ des lignes que vous voulez analyser ? : ")
for event in ress:
    # Initialisation chaine de carcatere
    if event.startswith(depart):
        texte=event.split(" ")
        ipsrc=texte[2].split(".")
        ipdst=texte[4].split(".")
        if texte[5] == "Flags":
            evenement=texte[0]+';'+texte[2]+';'+texte[4]+';'+texte[6]
            if texte[6] == "[S],":
                evenement=evenement+';'+texte[8]
                if texte[-2] == "length":
                    texte[-1].strip(":")
                    evenement=evenement+';'+';'+texte[-1]
                else:
                    length = texte[-2].strip(":")
                    evenement=evenement+';'+';'+length
            if texte[6] == "[P.],":
                evenement=evenement+';'+texte[8]+';'+texte[10]+';'+texte[-1]
            if texte[6] == "[.],":
                evenement=evenement+';'+';'+texte[8]+';'+texte[-1]
            if texte[6] == "[S.],":
                evenement=evenement+';'+texte[8]+';'+texte[10]
        else:
            evenement=texte[0]+';'+texte[2]+';'+texte[4]+';'
        resultat.append(evenement+'\n')
        if len(ipsrc)>1:
            del ipsrc[-1]
            stripsrc = ".".join(ipsrc)
        else:
            stripsrc=ipsrc[0]
        try:
            ip[stripsrc]
        except KeyError:
            ip[stripsrc]=1
        else:
            ip[stripsrc]+=1
    
            
with open('resultat.csv','w',newline='') as fhcsv:
    fhcsv.write('temps;Adresse IP source;Adresse IP de destination;Flag;Numero de sequence;Numero accuse de reception;Taille du paquet;\n')
    for i in resultat:    
        fhcsv.write(i)
print("------ \n")
print("Tableau Importé en format CSV ! \n")
print("Nom du fichier : resultat.csv \n")
print("------ \n")
print("Voici les adresses IP qui émettent le plus au sein du réseau : \n")

print(sorted(ip.items(), key=lambda item: item[1]))
             
fhcsv.close()
fh.close()