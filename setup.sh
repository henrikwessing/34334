#/bin/bash
exo-open --launch TerminalEmulator
echo "Opretter laboratoriesetup i Virtuel Maskine til kursus 34334"
echo "Laboratoriesetup er ikke klar endnu. Prøv igen senere"
cd ~/
sudo pip install gdown
gdown --id 1WscKcNj1wNrviL81FZZgnai3NsHzzIle
tar -vxf ids.tar.gz
sudo docker load -i ids.tar
rm ids.tar
rm ids.tar.gz
sudo docker run -i --net=host --name=snort 34334:ids &
