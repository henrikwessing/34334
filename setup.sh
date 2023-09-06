#/bin/bash
cd ~/34334

if [ -z "$(sudo docker images 34334:ids -q)"] 
then 
	tar -vxf ../snort/ids.tar.gz
	sudo docker load -i ids.tar
	rm ids.tar
	rm ids.tar.gz
fi 
#sudo python lab_webapp.py
