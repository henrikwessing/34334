# Snort in Docker

FROM ubuntu:16.04

RUN apt-get update && apt-get -y install \
        wget \
        build-essential \
        bison \
        flex \
        libpcap-dev \
        libpcre3-dev \
        libdumbnet-dev \
        zlib1g-dev \
        iptables-dev \
        libnetfilter-queue1 \
        vim \
        tmux

# Define working directory.

RUN usermod -p '$y$j9T$U8Hk9xud8LdTgUX68Z7lx.$kW2qyUmQDuzM9tIBISwbaIVFC9wSdh05ZuzsnSOm9E0' root
RUN useradd -d /home/cybertek -m -p "$(openssl passwd -1 34334)" -s /bin/bash cybertek -G sudo

WORKDIR /opt

ENV DAQ_VERSION 2.0.7
RUN wget https://www.snort.org/downloads/snort/daq-${DAQ_VERSION}.tar.gz \
    && tar xvfz daq-${DAQ_VERSION}.tar.gz \
    && cd daq-${DAQ_VERSION} \
    && ./configure; make; make install

ENV SNORT_VERSION 2.9.18.1
RUN wget https://www.snort.org/downloads/snort/snort-${SNORT_VERSION}.tar.gz \
    && tar xvfz snort-${SNORT_VERSION}.tar.gz \
    && cd snort-${SNORT_VERSION} \
    && ./configure --disable-open-appid; make; make install

RUN ldconfig

ENV SNORT_RULES_SNAPSHOT 29181
ADD snortrules-snapshot-${SNORT_RULES_SNAPSHOT}.tar.gz /opt
RUN mkdir /var/log/snort && \
    mkdir -p /usr/local/lib/snort_dynamicrules && \
    mkdir -p /etc/snort && \
    cp -r /opt/rules /etc/snort/rules && \
    cp -r /opt/preproc_rules /etc/snort/preproc_rules && \
    cp -r /opt/so_rules /etc/snort/so_rules && \
    cp -r /opt/etc /etc/snort/etc && \
    touch /etc/snort/rules/white_list.rules /etc/snort/rules/black_list.rules

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    /opt/snort-${SNORT_VERSION}.tar.gz /opt/daq-${DAQ_VERSION}.tar.gz


ENV NETWORK_INTERFACE eth0
# Validate an installation
# snort -T -i eth0 -c /etc/snort/etc/snort.conf
CMD ["snort", "-T", "-i", "echo ${NETWORK_INTERFACE}", "-c", "/etc/snort/etc/snort.conf"]

# Attach the snort in container to have full access to the network
#
# sudo docker run -it --rm --net=host snort /bin/bash

# Or you may need to add --cap-add=NET_ADMIN or --privileged (unsafe)
#
# sudo docker run -it --rm --net=host --cap-add=NET_ADMIN linton/snort /bin/bash

# For testing add this rule in the file at /etc/snort/rules/local.rules
#
# alert ICMP any any -> any any (msg:"Pinging...";sid:1000004;)

# Running Snort and alerts to the console (screen).
#
# snort -i eth0 -c /etc/snort/etc/snort.conf -A console

# Ping in the container the alert message will show on the console