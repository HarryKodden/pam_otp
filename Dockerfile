FROM ubuntu:latest
MAINTAINER harry@e-tunity.nl

RUN apt-get update

RUN apt-get install -y build-essential
RUN apt-get install -y autoconf
RUN apt-get install -y shtool
RUN apt-get install -y libpam-dev
RUN apt-get install -y libcurl4-gnutls-dev
RUN apt-get install -y libgcrypt20 libgcrypt20-dev
RUN apt-get install -y libldap2-dev

RUN apt-get install -y git
RUN git clone https://github.com/HarryKodden/pam_otp.git

RUN cd pam_otp && ln -s /usr/bin/shtool . && autoconf && ./configure && make && make install && make test && make clean

CMD ["pam_otp/test"]