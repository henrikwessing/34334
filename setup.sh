#/bin/bash
cd ~/34334

if [ -z "$(sudo docker images 34334:ids -q)"] 
then 
	tar -vxf ids.tar.gz
	sudo docker load -i ../snort/ids.tar
	rm ids.tar
	rm ids.tar.gz
fi 
#sudo python lab_webapp.py
