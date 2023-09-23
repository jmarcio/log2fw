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
import glob
import select

import signal
import atexit
from subprocess import *
import threading

import re
import time
from datetime import datetime

import argparse as ap
import configparser as cp
import jmSyslog
from  jmVersion import *

import math as m
import numpy as np
import pandas as pd

# -----------------------------------------------------------------------------
#
#

#
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
  ok = False
  friends = None
  for s in sections:
    try:
      friends = config.get(s, 'friends')
      datadir = config.get(s, 'datadir')
      ok = True
    except Exception as e:
      pass
    if ok:
      break
  if friends is None:
    return 1

  friends = [f for f in friends.split('\n') if f != '']

  lines = []
  lines.append('#! /bin/bash')
  lines.append('')
  lines.append('iptables -F {:s}'.format(cli.chain))
  fmt = 'iptables -A {:s} -p tcp -s {:18s} -j ACCEPT'
  for f in friends:
    lines.append(fmt.format(cli.chain, f))
  lines.append('')

  if cli.verbose:
    print('\n'.join(lines))

  fname = 'friends-iptables.sh'
  fpath = os.path.join(datadir, fname)
  try:
    with open(fpath, 'w') as fout:
      fout.write('\n'.join(lines))
    os.chmod(fpath, 0o755)
  except Exception as e:
    pass

  if cli.doit:
    try:
      log.log('* {:10s} - updating iptables firewall'.format(cli.chain))
      cp = run([fpath])
      if cp.returncode != 0:
        log.log("  iptables ERROR : {:}".format(cp.returncode))
    except Exception as e:
      log.log('   Exception caught {:}'.format(e))

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
  import sys

  log = jmSyslog.JmLog("mk-friends")
  #log.log(f"* Started at {time.strftime('%X')}")

  cli = getCliArgs()
  if cli.version:
    print(VersionStr())
    sys.exit(0)

  config = None
  bConf = os.path.basename(sys.argv[0]).replace('.py', '.conf')
  bConf = 'log2fw.conf'
  confDirs = ['/etc/log2fw', '/opt/log2fw/etc']
  for bDir in confDirs:
    fConfig = os.path.join(bDir, bConf)
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
