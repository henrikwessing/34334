#/bin/bash
cd ~/34334
sudo apt-get install iperf

if [ -z "$(sudo docker images 34334:ids -q)" ] 
then 
	tar -vxf ../snort/ids.tar.gz
	sudo docker load -i ids.tar
	rm ids.tar
fi 
# sudo python lab_webapp.py
