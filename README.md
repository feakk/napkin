# Developed by Paul Haas, licensed under the GNU Public License version 3.0 

Napkin is a Linux shell script used to extract interesting information from Burp Suite Professional's (http://portswigger.net/burp/) saved session files. Output is divided into individual text files in an output directory.

Napkin requires xmlstarlet, which is available from most Linux distributions. For Debian derivatives run: 

sudo apt-get install xmlstarlet

To run:
	Run Burp Suite Professional
	Save session file
	Copy session file into napkin directory with extension .zip or .session
	./napkin.sh

