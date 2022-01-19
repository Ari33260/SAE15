fichier = open("test.txt", "r")
# = fichier.read().splitlines(keepends=True)
data = fichier.read().splitlines(keepends=True)
for lignes in range(20):
    print(data[lignes])
for event in data:
    if event.startswith('')
fichier.close()
