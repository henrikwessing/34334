FROM 34334:base

#RUN pip install scapy pysmbclient
RUN apt-get install -y winbind dhcping nginx
RUN apt-get install -y nano

#set dhclient.conf to be aggressive with dhcp requests
RUN echo 'retry 10;' >> /etc/dhcp/dhclient.conf
RUN echo 'timeout 10;' >> /etc/dhcp/dhclient.conf

#fixup nsswitch so we can resolve wins
RUN sed 's/files dns/wins files dns/' /etc/nsswitch.conf >> /etc/nsswitch.conf

ADD start_vic.py /start_vic.py
#add configs for supervisord
ADD supervisor_vics.conf /etc/supervisor/conf.d/supervisor_vics.conf
RUN service nginx start




