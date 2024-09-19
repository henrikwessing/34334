#/bin/bash
cd ~/34334
sudo apt-get install iperf

if [ -z "$(sudo docker images 34334:ids -q)" ] 
then 
	wget wget https://files.cyberteknologi.dk/ids-$(uname -m).tar.gz -O ids.tar.gz
	tar -vxf ids.tar.gz && rm ids.tar.gz 
	sudo docker load -i ids.tar
	rm ids.tar
fi
 
sudo python lab_webapp.py
