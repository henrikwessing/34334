FROM debian:bullseye

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get -y install tzdata
RUN apt-get install -y nano curl gpg procps supervisor \ 
	&& rm -rf /var/lib/apt/lists/*
RUN curl -s https://deb.frrouting.org/frr/keys.asc | gpg --dearmor -o /usr/share/keyrings/frrouting.gpg
ARG FRRVER="frr-8"
RUN echo "deb [signed-by=/usr/share/keyrings/frrouting.gpg] https://deb.frrouting.org/frr \
	$(lsb_release -s -c) $FRRVER" > /etc/apt/sources.list.d/frr.list > /dev/null
RUN apt-get update && \
    apt-get install -y frr frr-pythontools && \
    rm -rf /var/lib/apt/lists/*

# Own the config / PID files
RUN mv /etc/frr/daemons /etc/frr/daemons_original

COPY ospfd.conf /etc/frr/ospfd.conf
COPY zebra*.conf /etc/frr/
COPY ripd*.conf /etc/frr/
COPY daemons /etc/frr/


RUN mkdir -p /var/run/frr
RUN chown -R frr:frr /etc/frr /var/run/frr


# Default CMD starts watchfrr
COPY --chmod=0755 docker-start /usr/lib/frr/docker-start
#CMD ["/usr/lib/frr/docker-start"]
RUN  mkdir -p /var/log/supervisor && mkdir -p /etc/supervisor/conf.d
#supervisor base configuration
ADD supervisor.conf /etc/supervisor/supervisor.conf
#add conf for dhclient
ADD supervisor_dhclient.conf /etc/supervisor/conf.d/supervisor_dhclient.conf


CMD ["supervisord", "-c", "/etc/supervisor/supervisor.conf"]

