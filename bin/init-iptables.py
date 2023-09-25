#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#

#
# This script does...
#
# History : xx/xx/xxxx - Jose-Marcio Martins da Cruz
#           Just created
#

import os
import sys
from subprocess import *
from datetime import datetime

import argparse as ap
import configparser as cp
import jmSyslog
from  jmVersion import VersionStr

# -----------------------------------------------------------------------------
#
#

def now():
  return datetime.now().timestamp()


# -----------------------------------------------------------------------------
#
#
#
def main(cli, config):
  sections = config.sections()
  datadir = None

  #
  # Create new chains
  #
  lines = []
  lines.append('#! /bin/bash')
  lines.append('')
  lines.append('# Set default policy for chain INPUT')
  lines.append('iptables -P INPUT ACCEPT')

  hdr = "{:12s} {:10s} {:}".format('Section', 'Chain', 'Enabled')
  print(hdr)
  print('-' * len(hdr))
  lines.append('# Check managed chains')

  for section in sections:
    chain = config.get(section, "chain")
    enabled = config.getboolean(section, 'enabled')
    if datadir is None:
      datadir = config.get(section, 'datadir')

    print(f"{section:12s} {chain:10s} {enabled:}")
    if enabled:
      cmd = f'iptables -n -L {chain:10} >/dev/null 2>&1 || iptables -N {chain:}'
      lines.append(cmd)
  chain = 'Friends'
  lines.append(f'# Create Chain {chain}')
  cmd = f'iptables -n -L {chain:10} >/dev/null 2>&1 || iptables -N {chain:}'
  lines.append(cmd)
  lines.append('')

  fname = 'iptables-chains.sh'
  fpath = os.path.join(datadir, fname)
  try:
    with open(fpath, 'w') as fout:
      fout.write('\n'.join(lines))
    os.chmod(fpath, 0o755)
  except Exception as e:
    print(f'Exception when opening file {fpath:} : {e:}')
    pass

  if cli.verbose:
    print()
    print('{:s} {:^40s} {:s}'.format('=' * 16, fpath, '=' * 16))
    print('\n'.join(lines))

  if cli.doit:
    if os.geteuid() == 0:
      try:
        cp = run([fpath])
        if cp.returncode != 0:
          print("  iptables ERROR : {:}".format(cp.returncode))
      except Exception as e:
        print(f'Exception when running {fpath:} : {e:}')
    else:
      print('==== > ERROR : must be root to use --doit option')

  #
  # Define iptables rules
  #
  sections = [s for s in sections if config.getboolean(s, 'enabled')]
  LHeader = [
    "*filter",
    ":INPUT ACCEPT [0:0]",
    ":FORWARD DROP [0:0]",
    ":OUTPUT ACCEPT [0:0]",
  ]
  for s in sections:
    chain = config.get(s, 'chain')
    LHeader.append(f':{chain:} - [0:0]')
  chain = 'Friends'
  LHeader.append(f':{chain:} - [0:0]')

  LInput = [
    "# Connections managed by log2fw",
    "-A INPUT -p tcp -m state --state NEW -m tcp -j Friends", "# "
  ]
  for section in sections:
    chain = config.get(section, "chain")
    enabled = config.getboolean(section, 'enabled')
    if not enabled:
      continue
    pstr = config.get(section, 'ports')
    ports = [int(x) for x in pstr.split(',')]
    for p in ports:
      s = f'-A INPUT -p tcp -m tcp --dport {p:} -j {chain:}'
      LInput.append(s)
  rule = "# Accept all connections already open"
  LInput.append(rule)
  rule = "-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT"
  LInput.append(rule)

  rule = "# Accept new connections to log2fw managed ports"
  LInput.append(rule)
  for section in sections:
    chain = config.get(section, "chain")
    enabled = config.getboolean(section, 'enabled')
    if not enabled:
      continue
    pstr = config.get(section, 'ports')
    ports = [int(x) for x in pstr.split(',')]
    for p in ports:
      s = f'-A INPUT -p tcp -m state --state NEW -m tcp --dport {p:} -j ACCEPT'
      LInput.append(s)
  LInput.extend([
    "# Other protocols",
    "-A INPUT -p icmp -j ACCEPT",
    "-A INPUT -i lo -j ACCEPT",
    "-A INPUT -p udp -m udp --dport 53 -j ACCEPT",
    "-A INPUT -p tcp -m state --state NEW -m tcp --dport 53 -j ACCEPT",
    "-A INPUT -j REJECT --reject-with icmp-host-prohibited",
  ])

  LForward = [
    "# Chain FORWARD",
    "-A FORWARD -j REJECT --reject-with icmp-host-prohibited",
  ]
  LFriends = [
    "# Chain Friends (minimal)",
    "-A Friends -s 127.0.0.0/8 -p tcp -j ACCEPT",
    "-A Friends -s 10.0.0.0/8 -p tcp -j ACCEPT",
    "-A Friends -s 192.168.0.0/16 -p tcp -j ACCEPT",
  ]
  LTail = [
    "# Finally... COMMIT all this stuff",
    "COMMIT",
    '#'
  ]

  lines = LHeader + LInput + LForward + LFriends + LTail

  fname = 'rules.log2fw'
  fpath = os.path.join(datadir, fname)
  try:
    with open(fpath, 'w') as fout:
      fout.write('\n'.join(lines))
    os.chmod(fpath, 0o755)
  except Exception as e:
    print(f'Exception when opening file {fpath:} : {e:}')

  if cli.verbose:
    print('{:s} {:^40s} {:s}'.format('=' * 16, fpath, '=' * 16))
    print('\n'.join(LHeader))
    print('\n'.join(LInput))
    print('\n'.join(LForward))
    print('\n'.join(LFriends))
    print('\n'.join(LTail))

  return 0


# -----------------------------------------------------------------------------
#
#  ####    ####   #    #  ######
# #    #  #    #  ##   #  #
# #       #    #  # #  #  #####
# #       #    #  #  # #  #
# #    #  #    #  #   ##  #
#  ####    ####   #    #  #
#
def appLoadConfigFile(fconfig=None):
  if fconfig is None:
    return None

  if not os.path.isfile(fconfig):
    return None

  config = cp.ConfigParser(interpolation=cp.ExtendedInterpolation(),
                           default_section="defaults",
                           strict=True)

  config.BOOLEAN_STATES['Vrai'] = True
  config.BOOLEAN_STATES['Faux'] = False

  config.read(fconfig)

  return config


# -----------------------------------------------------------------------------
#
#
def appShowConfigFile(config=None):
  if config is None:
    return
  sections = config.sections()
  for ks in sections:
    print("[{:s}]".format(ks))
    s = config[ks]
    for k in s.keys():
      lines = s[k].split('\n')
      if len(lines) > 1:
        print("  {:20s} :".format(k))
        for line in lines:
          if len(line) == 0:
            continue
          print("    {:s}".format(line))
      else:
        print("  {:20s} : {:s}".format(k, s[k]))

    print()


# -----------------------------------------------------------------------------
#
#
def getCliArgs():
  parser = ap.ArgumentParser()

  parser.add_argument('--debug', help='', action="store_true")
  parser.add_argument('--verbose', help='', action="store_true")
  parser.add_argument('--version', help='', action="store_true")

  parser.add_argument('--chain',
                      help='What to do (monitor)',
                      default='Friends',
                      type=str)
  parser.add_argument('--doit', help='', action="store_true")

  parser.add_argument('--showconf', help='', action="store_true")
  parser.add_argument('--showargs', help='', action="store_true")

  cli = parser.parse_args()

  if cli.debug:
    cli.verbose = True

  return cli


# -----------------------------------------------------------------------------
#
#
def showArgs(cli, show=False, fName=None):
  args = []
  for k in vars(cli).items():
    lOut = '  {:20s} : {:}'.format(k[0], k[1])
    args.append(lOut)
  args.append('')

  if show:
    print('\n'.join(args))

  if not fName is None:
    with open(fName, "w") as fout:
      fout.write('\n'.join(args) + '\n')

  return args


# =============================================================================
#
#  ####   #          #
# #    #  #          #
# #       #          #
# #       #          #
# #    #  #          #
#  ####   ######     #
#
if __name__ == '__main__':

  log = jmSyslog.JmLog("init-iptables")
  #log.log(f"* Started at {time.strftime('%X')}")

  cli = getCliArgs()
  if cli.version:
    print(VersionStr())
    sys.exit(0)

  config = None
  bConf = os.path.basename(sys.argv[0]).replace('.py', '.conf')
  bConf = 'log2fw.conf'
  confDirs = ['/etc/log2fw', '/opt/log2fw/etc', '/opt/log2fw-tools/etc']
  for bDir in confDirs:
    fConfig = os.path.join(bDir, bConf)
    print(fConfig)
    if os.path.isfile(fConfig):
      config = appLoadConfigFile(fConfig)
      log.log(f'Using configuration file {fConfig:}')
      break
  if config is None:
    msg = f'===> Configuration file {bConf:} not found'
    print(msg)
    sys.exit(1)

  if cli.showconf:
    appShowConfigFile(config)
  if cli.showargs:
    showArgs(cli, True)
  if cli.showconf or cli.showargs:
    sys.exit(0)

  sys.exit(main(cli, config))
