# log2fw

`log2vw` is a set of scripts to be used to monitor and analyse log files in order to generate firewall rules based on the activity detected on these files.

## History

The idea comes back to the beginning of years 2000. At those days we needed a solution to to this on Sun Solaris boxes. The first version of `log2fw` was written in Perl and had another name. So now, I've decided to rewrite it from scratch under Python with some lacking features and some improvements. But the main idea remains the same: continuos monitoring of log files looking for regular expressions.

## Features

* Monitor log files and generate iptables rules based on substrings and regular expressions found in log files;
* easy configuration;
* comes with three configured profiles: `ssh`, `apache` and `postfix`. Create new profiles based on included placeholder profiles;
* improve profiles just adding new substrings and regular expressions to look for in log files;
* a single instance will manage all configured and enabled profiles;

## Requirements

To run `log2fw`, you just need a Linux box with:

* iptables
* Python 3 (>= 3.7)
* Python modules numpy and pandas

## Installation

Get `log2fw' stuff from github:
~~~
cd /opt
git clone https://github.com/jmarcio/log2fw
~~~

**OBS:** This package was created to be installed below `/opt`, but you can install elsewhere if you want, e.g., `/usr/local/`. In this case, you must modify just two files: the startup systemd script (`/etc/systemd/system/log2fw`) and the option `fwdir` in configuration file (`/etc/log2fw/log2fw.conf`)

### Install auxiliary files

~~~
mkdir -p /var/lib/log2fw

mkdir -p /etc/log2fw
cp -p etc/log2fw.conf /etc/log2fw/
chown -hR root: /etc/log2fw

cp -p doc/install/etc/default/log2fw /etc/default
chown root: /etc/default/log2fw

cp -p doc/install/etc/rsyslog.d/40-log2fw.conf /etc/rsyslog.d
systemctl restart rsyslog
~~~

## Configure log2fw (/etc/log2fw/log2fw.conf)

Configuration file is self-explanatory (I hope). `default` section contains default values for all profiles.

There are three pre-configured profiles: `apache`, `postfix`, `ssh` and 'nginx`. Take a look to see if it fits your needs and adapt them.

Two of the most important configuration options are `substr` and `regex`. This options define what will be looked in log files. It's important to understand them: *substr* are pieces of text that will be looked as they are defined while *regex* are regular expressions and can be used to define complex strings. Whenever possible privilegiate *substr* as subsring matching check is much faster than *regex*.

You can define *substr* and *regex* both inside `log2fw.conf` file or inside text files inside configuration directory. File names have the pattern `ProfileName-substr.txt` and `ProfileName-regex.txt`. Empty lines or lines beginning with an '#' are ignored. It seems less error prone to use these files than putting data inside the configuration file.

There are also three other "placeholder" profiles: `cyrus`, `dovecot` and `zimbra`. If you use them, just complete configuration, mainly with substrings and regular expressions. `zimbra` profile is particular as it integrates different parts of software with different log formats. If you want to use log2fw to monitor zimbra log files, you'll probably need to split it in multiple profiles: MTA, MSP (use postfix profile) and IMAP or POP profiles.

## iptables configuration

Initial `iptables` configuration may be a critical operation. So, it's recommended to do it manually. Hopefully, two scripts - `init-iptables.py` and `mk-friends.py` - can help you.

### iptables log2fw rules

First of all, run `init-iptables.py` script. This will create two files inside `/var/lib/log2fw` directory:

* `iptables-chains` - a shell script to create iptables chains used by log2fw
* `rules.log2fw`- an iptables rules files in the format used by `iptables-save` and `iptables-restore`.

~~~
/opt/log2fw/bin/init-iptables.py --verbose
~~~

The second part of the following, integrating log2fw rules, may be more complex if you already use iptables for something else. In this case, you must merge `rules.save` and `rules.log2fw` files to fit your needs. If this is not the case you may just execute the following commands.

~~~
cd /var/lib/log2fw
# Create iptables chains for each profile managed by log2fw
./iptables-chains.sh
# save your current iptables rules
iptables-save > rules.save
# OPTIONAL but RECOMMENDED: test log2fw rules
iptables-apply -t 60 rules.log2fw
# apply them
iptables-restore < rules.log2fw
~~~

### Friends IP network addresses

If you modified `friends` options in your configuration file, adding or removing IP addresses or networks, you shall run this script (as root). You must run this script each time you modify this option in your configuration file.

~~~
/opt/log2fw/bin/mk-friends.py --chain Friends --verbose --doit
~~~

A file `friends-iptables.sh` will be created inside directory  `/var/lib/log2fw` directory. If you use option `--doit`, iptables rules will be updated. If not, you must run `friends-iptables.sh` bash script manually.

## starting log2fw

Finally, just start `log2fw` daemon, check its log files and enjoy.

~~~
systemctl daemon-reload
systemctl enable log2fw
systemctl start log2fw
~~~

