#!/bin/bash
sudo apt-get update
sudo apt-get install g++
sudo apt-get install automake autoconf libtool libjansson-dev libcurl4-openssl-dev

# compiling libecap
cd libecap-1.0.0/ 
./configure && make && sudo make install

# compiling virus total interfaces
cd ../c-vtapi-master/ 
autoreconf -fi 
autoreconf -fi # old bug - needs to run twice...
./configure && make && sudo make install


# compiling ecap_adapter
cd ../ecap_clamav_adapter-2.0.0/
env LIBS=" -lcvtapi" ./configure && make && sudo make install

# compiling squid
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

# moving squid configuration file
cd ..
yes | sudo cp -rf squid.conf /etc/squid/squid.conf

# moving ransomware signatures files
sudo cp sealinit_sig /etc
sudo cp openinit_sig /etc

# additional operations on squid log files
sudo touch /var/run/squid.pid /var/log/squid/cache.log /var/log/squid/access.log 
sudo chmod a+w /var/run/squid.pid /var/log/squid/cache.log /var/log/squid/access.log

# tell the loader to recognize the libraries in /usr/local/lib
sudo ldconfig 

# set the proxy as system wide
sudo gsettings set org.gnome.system.proxy.http host '127.0.0.01'
sudo gsettings set org.gnome.system.proxy.http port 3128
sudo gsettings set org.gnome.system.proxy mode 'manual'
