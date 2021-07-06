#!/bin/bash
# Setup shell to install all needed Packages and configure them

#https://stackoverflow.com/questions/1298066/how-to-check-if-package-installed-and-install-it-if-not
# Proofs if apt is installed, if not the install and config needs to be manual executed
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
	
	# Checks if the maliciousevents folder is not existing, if yes create a virtual environment
	if [ $(ls -d */ | grep -c "maliciousevents") -eq 0 ];
	then
		python3 -m venv maliciousevents
	fi
	
	# Activate the virtual environment
	source maliciousevents/bin/activate
	# Installing wheel, needs to be preinstalled
	pip3 install wheel==0.36.2
	
	# Install all needed requirements out of the requirements if its existing
	if [ $(ls -al | grep -c "requirements.txt") -eq 0 ];
	then
		echo "Missing file - requirements.txt."
		exit
	else
		python3 -m pip install -r ./requirements.txt
	fi

  # Copy the modified DAGMM package to the virtual environment
	cp -r ./lib/. ./maliciousevents/lib/python3.8/site-packages/

	# Deactivates the virtual environment
	deactivate

	
	# Create a folder to save all R Packages later
	mkdir ~/.R
	Rscript setup_requirements.R

else
	echo "Not able to install, without apt."
fi
