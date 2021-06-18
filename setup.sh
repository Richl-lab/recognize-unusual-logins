#!/bin/bash
#Shell um alle nötigen Pakete und Konfigurationen laden/erstellen

#https://stackoverflow.com/questions/1298066/how-to-check-if-package-installed-and-install-it-if-not
#Prüft ob der Packetmanager apt verfügbar ist, falls nicht müssen die Pakete/EInstellungen manuell erfolgen
if [ $(dpkg-query -W -f='${Status}' apt | grep -c "ok installed") -eq 1 ];
then 
	#Installieren von r/python/pip/env, falls es nicht geht muss es manuell durchgeführt werden
	{
		sudo apt-get install r-base
		sudo apt-get install python3.8

		sudo apt-get install python3-pip
		sudo apt-get install python3-venv
	} || {
		echo "Not able to install, all packages"
		exit
	}
	
	#Prüft ob ein ordner maliciousevents schon existiert falls nicht wird ein dementsprechendes virtuelle Umgebung erstellt
	if [ $(ls -d */ | grep -c "maliciousevents") -eq 0 ];
	then
		python3 -m venv maliciousevents
	fi
	
	#Aktiviert die Umgebung
	source maliciousevents/bin/activate
	#Installiert wheel, ist vorher notwendig um wheels für sklearn&pyod zu erstellen
	pip3 install wheel==0.36.2
	
	#Installiert die Python Bibliotheken, wenn das requirements file verfügbar ist
	if [ $(ls -al | grep -c "requirements.txt") -eq 0 ];
	then
		echo "Missing file - requirements.txt."
		exit
	else
		python3 -m pip install -r ./requirements.txt
	fi

  #Fügt die bearbeitete Version von dagmm hinzu
	cp -r ./lib/. ./maliciousevents/lib/python3.8/site-packages/

	#Deaktiviert die Virtuelle Umgebung wieder
	deactivate
	
	#Erstellt ein Link zu dem R Programm um es überall ausführen zu können
	#Falls der Ordner ~/.local/bin nicht in der PATH Variable verfügbar ist wird dieser erstellt+hinzugefügt
	if [ $(echo $PATH | grep -c "/.local/bin") -eq 1 ];
	then
		ln -s -r FindMaliciousEvents.R ~/.local/bin/FindMaliciousEvents
	else
		mkdir ~/.local/bin
		echo "PATH=$PATH:~/.local/bin" >> ~/.bashrc
		. ~/.bashrc
		ln -s -r FindMaliciousEvents.R ~/.local/bin/FindMaliciousEvents
	fi
	
	#Erstellen eines Ordners um anschließend die R Site packages darin zu speichern
	mkdir ~/.R

else
	echo "Not able to install, without apt."
fi
