# log2fw

`log2vw` is a set of scripts to be used to monitor and analyse log files in order to generate firewall rules based on the activity detected on these files.

## History

The idea comes back to the beginning of years 2000. At those days we needed a solution to to this on Sun Solaris boxes. The first version of `log2fw` was written in Perl and had another name. So now, I've decided to rewrite it from scratch under Python with some lacking features and some improvements. But the main idea remains the same : continuos monitoring of log files looking for regular expressions.

## Requirements

To run `log2fw`, you just need a Linux box with :
* iptables
* Python 3 (>= 3.7)
* Python modyles numpy and pandas

## Installation

Get `log2fw' stuff from github :
~~~
cd /opt
git clone https://github.com/jmarcio/log2fw
~~~

**OBS :** This package was created to be installed below `/opt`, but you can install elsewhere if you want, e.g., `/usr/local/`. In this case, you must modify just two files : the startup systemd script (`/etc/systemd/system/log2fw`) and the option `fwdir` in configuration file (`/etc/log2fw/log2fw.conf`)

### Install auxiliary files

~~~
mkdir -p /var/lib/log2fw

mkdir -p /etc/log2fw
cp -p etc/log2fw.conf /etc/log2fw/
chown -hR root: /etc/log2fw

cp -p doc/install/etc/default/log2fw /etc/default
chown root: /etc/default/log2fw
~~~

## Configure log2fw (/etc/log2fw/log2fw.conf)

## iptables configuration

### iptables log2fw rules

~~~
/opt/log2fw/bin/init-iptables.py --verbose
~~~

### Friends IP network addresses

~~~
/opt/log2fw/bin/mk-friends.py --chain Friends --verbose --doit
~~~

## starting log2fw

~~~
systemctl daemon-reload
systemctl enable log2fw
systemctl start log2fw
~~~

