FROM 34334:base

#install vrrpd, lldpd and quagga
RUN apt-get install -y lldpd 
RUN apt-get install -y frr
RUN apt-get install -y openssh-server
RUN apt-get install -y geany nano mousepad


#add the quagga scripts
USER frr
ADD daemons /etc/frr/daemons
ADD ospfd.conf /etc/frr/ospfd.conf
ADD zebra*.conf /etc/frr/
ADD ripd*.conf /etc/frr/

USER root
ADD sshd_config /etc/ssh/sshd_config

#add supervisord script and startup script and disable initial dhclient
#ADD start_vrrpd.py /start_vrrpd.py
#ADD supervisor_vrrpd.conf /etc/supervisor/conf.d/supervisor_vrrpd.conf
RUN touch /home/cybertek/.XAuthority
RUN rm -f /etc/supervisor/conf.d/supervisor_dhclient.conf
#CMD sysctl -w net.ipv4.ip_forward=1
