# squid-av

## Build Instructions

At the beginning, run:
```sh
$ sudo apt-get update
$ sudo apt-get install g++
$ sudo apt-get install automake autoconf libtool libjansson-dev libcurl4-openssl-dev
```

Add a new line to the file `/etc/ld.so.conf`: 
```sh
/usr/local/lib
```
Run:
```sh
$ sudo ldconfig
```


### libecap-1.0.0:

```sh
$ ./configure && make && sudo make install
```


### c-vtapi-master:

```sh
$ autoreconf -fi ./configure && make && sudo make install
```


### ecap_clamav_adapter-2.0.0:

replace `"XXX"` in `src/Antivirus.cc` to our VT public key. Then run:
```sh
$ ./configure
```
in `src/Makefile`, edit the line 
```sh
LIBS = 
```
to
```sh 
LIBS = -lcvtapi
```
Then, run:
```sh
$ make && sudo make install
```


### squid-3.5.22:

```sh
$ ./configure --prefix=/usr \
--localstatedir=/var \
--libexecdir=${prefix}/lib/squid \
--datadir=${prefix}/share/squid \
--sysconfdir=/etc/squid \
--with-default-user=proxy \
--with-logdir=/var/log/squid \
--with-pidfile=/var/run/squid.pid \
--enable-ecap
```
Then:
```sh
$ sudo make && sudo make install
```
Replace `/etc/squid/squid.conf` with `squid.conf` supplied here.
You can do it with (under project root directory):
```sh
yes | sudo cp -rf squid.conf /etc/squid/squid.conf
```

Run:
```sh
sudo touch /var/run/squid.pid /var/log/squid/cache.log /var/log/squid/access.log 
sudo chmod a+w /var/run/squid.pid /var/log/squid/cache.log /var/log/squid/access.log 
```

At last, change system wide proxy settings:
http://askubuntu.com/questions/342906/change-proxy-settings-in-ubuntu
with our specific IP and port.


## Debug squid

```sh
gdb /usr/sbin/squid
r -NCd1
```
