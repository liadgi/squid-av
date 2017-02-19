#!/bin/bash
sudo apt-get update
sudo apt-get install g++
sudo apt-get install automake autoconf libtool libjansson-dev libcurl4-openssl-dev

cd libecap-1.0.0/ 
./configure && make && sudo make install

cd ../c-vtapi-master/ 
autoreconf -fi 
autoreconf -fi 
./configure && make && sudo make install

cd ../ecap_clamav_adapter-2.0.0/
env LIBS=" -lcvtapi" ./configure && make && sudo make install

cd ../squid-3.5.22/
autoreconf -f -i
./configure --prefix=/usr \
--localstatedir=/var \
--libexecdir=${prefix}/lib/squid \
--datadir=${prefix}/share/squid \
--sysconfdir=/etc/squid \
--with-default-user=proxy \
--with-logdir=/var/log/squid \
--with-pidfile=/var/run/squid.pid \
--enable-ecap 
sudo make && sudo make install

cd ..
yes | sudo cp -rf squid.conf /etc/squid/squid.conf

sudo touch /var/run/squid.pid /var/log/squid/cache.log /var/log/squid/access.log 
sudo chmod a+w /var/run/squid.pid /var/log/squid/cache.log /var/log/squid/access.log

sudo ldconfig 
