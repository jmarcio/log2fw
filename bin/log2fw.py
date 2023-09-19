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
import select

import signal
import atexit
from subprocess import *
import threading

#import asyncio

import time

import glob
#import psutil

#import fnmatch as fn
import re
#import datetime
from datetime import datetime

import argparse as ap
import configparser as cp
import jmSyslog
import jmTail

import math as m
import numpy as np

import pandas as pd

#import statistics  as st
#import scipy.stats as sst
#import seaborn     as sb

#import matplotlib.pyplot as plt


# =============================================================================
#
#
def dummy(cli):
  return 0


# -----------------------------------------------------------------------------
#
# #####   ####    ####   #        ####
#   #    #    #  #    #  #       #
#   #    #    #  #    #  #        ####
#   #    #    #  #    #  #            #
#   #    #    #  #    #  #       #    #
#   #     ####    ####   ######   ####
#
childPids = []
exitFlag = False

def killChildren():
  #print('* killChildren')
  #log.log('* killChildren')
  global exitFlag
  exitFlag = True
  for pid in childPids:
    #print('===> Killing ', pid)
    try:
      os.kill(pid, signal.SIGTERM)
    except Exception as e:
      pass


def sigHandler(signum, frame):
  #print('* Signal handler called with signal', signum)
  global exitFlag
  exitFlag = True
  killChildren()
  #exit(0)


exitFlag = False


#
#
#
def now():
  return datetime.now().timestamp()


def decode_conf_str_matches(cfProfile):
  expr = []
  regex = []

  expr_lines = cfProfile['expr']
  expr = []
  for line in expr_lines.split('\n'):
    line = line.strip()
    if line == '':
      continue
    expr.append(line)

  re_lines = cfProfile['regex']
  regex = []
  for line in re_lines.split('\n'):
    line = line.strip()
    if line == '':
      continue
    regex.append(line)

  return expr, regex


#
#
#
def lines_to_events(lines, expr=[], regex=[], profile='apache'):
  #
  #
  #
  def getDate(line, profile):
    if profile == 'apache':
      m = re.search('\[([^]]+)\]', line)
      if not m is None:
        sdate = m.group(1)
        dtime = datetime.strptime(sdate, '%d/%b/%Y:%H:%M:%S %z')
        tstamp = dtime.timestamp()
      else:
        tstamp = datetime.now().timestamp()
      return tstamp
    if profile in ['postfix', 'ssh']:
      regex = '([A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2})'
      m = re.search(regex, line)
      if not m is None:
        sdate = m.group(1)
        dtime = datetime.strptime(sdate, '%b %d %H:%M:%S')
        now = datetime.now()
        year = now.year
        if dtime.month > now.month:
          year -= 1
        dtime = dtime.replace(year=year, tzinfo=None)
        tstamp = dtime.timestamp()
      else:
        tstamp = datetime.now().timestamp()
      return tstamp

    return datetime.now().timestamp()

  #
  #
  #
  def getIPAddress(line):
    expr = '\[([0-9]+(?:\.[0-9]+){3})\]'
    m = re.search(expr, line)
    if not m is None:
      return m.group(1)
    expr = '([0-9]+(?:\.[0-9]+){3})'
    m = re.search(expr, line)
    if not m is None:
      return m.group(1)

    if False:
      ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
      if len(ip) > 0:
        return ip[0]
      ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
      if len(ip) > 0:
        return ip[0]

    return None

  #
  # M A I N
  #
  events = []

  for line in lines:
    for r in expr:
      if r in line:
        #line = line.decode('utf8')
        tstamp = getDate(line, profile)
        ip = getIPAddress(line)
        if not ip is None:
          evt = [tstamp, ip, r]
          evt = [tstamp, ip]
          events.append(evt)
        break

    for r in regex:
      if not re.search(r, line) is None:
        #line = line.decode('utf8')
        tstamp = getDate(line, profile)
        ip = getIPAddress(line)
        if not ip is None:
          evt = [tstamp, ip, r]
          evt = [tstamp, ip]
          events.append(evt)
        break

  return events


# -----------------------------------------------------------------------------
#
# #    #   ####   #    #     #     #####   ####   #####
# ##  ##  #    #  ##   #     #       #    #    #  #    #
# # ## #  #    #  # #  #     #       #    #    #  #    #
# #    #  #    #  #  # #     #       #    #    #  #####
# #    #  #    #  #   ##     #       #    #    #  #   #
# #    #   ####   #    #     #       #     ####   #    #
#
class MonitorContext():
  #
  def __init__(self, cli, profile, config):
    #
    #
    log.log(f"* MonitorContext init {profile:s} at {time.strftime('%X')}")
    self.profile = profile
    self.config = config

    self.debug = cli.debug
    self.verbose = cli.verbose

    #
    self.logfiles = []
    cfFiles = config['logfile'].split('\n')
    cfFiles = [f for f in cfFiles if f != '']
    lFiles = []
    for f in cfFiles:
      lFiles += glob.glob(f)
    self.logfiles = lFiles

    #
    self.tasks_log = []
    self.task_lines = None
    self.task_events = None
    self.task_dump = None

    self.loglines = []
    self.events = []
    self.blacklist = []
    self.need_update = False

    self.df_events = None
    self.last_read_event = 0
    self.df_blacklist = None

    if not cli.reset:
      if self.debug:
        print('Reading events and blacklist ', profile)
      self.read_events()
      self.read_blacklist()

    # update
    self.update_blacklist()
    self.dump_iptables()
    # save
    self.dump_events()
    self.dump_blacklist()

    self.expr, self.regex = decode_conf_str_matches(self.config)
    if self.debug:
      log.log('* {:10s} - Expr : {:d} - Regex : {:d}'.format(
        self.profile, len(self.expr), len(self.regex)))
      log.log('* {:10s} - Logfiles :'.format(self.profile))
      for f in self.logfiles:
        log.log('  * {:10s} - {:s}'.format(self.profile, f))

  #
  #
  def _df_to_list(self, df):
    llist = []
    for i, row in df.iterrows():
      e = []
      for c in df.columns:
        e.append(row[c])
      llist.append(e)
    return llist

  #
  #
  def read_events(self):
    log.log('  * {:10s} - read_events'.format(self.profile))

    fname = f'{self.profile:s}-events.csv'
    fname = os.path.join(self.config['datadir'], fname)
    columns = ['date', 'address']
    if os.path.isfile(fname):
      df = pd.read_csv(fname)
      for c in df.columns:
        if not c in columns:
          del df[c]
      now = datetime.now().timestamp()
      expire = float(self.config['expire'])
      self.df_events = df[df['date'] + expire > now].copy()
    else:
      self.df_events = pd.DataFrame([], columns=columns)
    self.events = self._df_to_list(self.df_events)

  #
  #
  def read_blacklist(self):
    log.log('  * {:10s} - read_blacklist'.format(self.profile))

    fname = f'{self.profile:s}-blacklist.csv'
    fname = os.path.join(self.config['datadir'], fname)
    columns = ['date', 'address']
    if os.path.isfile(fname):
      df = pd.read_csv(fname)
      for c in df.columns:
        if not c in columns:
          del df[c]
      now = datetime.now().timestamp()
      expire = float(self.config['expire'])
      self.df_blacklist = df[df['date'] + expire > now].copy()
    else:
      self.df_blacklist = pd.DataFrame([], columns=columns)
    self.blacklist = self._df_to_list(self.df_blacklist)

  #
  #
  def dump_events(self):
    if self.verbose:
      log.log('  * {:10s} - dump_events    : {:d} data items'.format(
        self.profile, len(self.events)))

    columns = ['date', 'address', 'expr']
    columns = ['date', 'address']
    events = self.events.copy()
    df = pd.DataFrame(events, columns=columns)
    if 'expr' in columns:
      del df['expr']
    fname = f'{self.profile:s}-events.csv'
    fname = os.path.join(self.config['datadir'], fname)
    df.to_csv(fname, index=False)

  #
  #
  #
  def dump_blacklist(self):
    if self.verbose:
      log.log('  * {:10s} - dump_blacklist : {:d} data items'.format(
        self.profile, len(self.blacklist)))

    columns = ['date', 'address', 'count']
    columns = ['date', 'address']
    blacklist = self.blacklist.copy()
    df = pd.DataFrame(blacklist, columns=columns)
    fname = f'{self.profile:s}-blacklist.csv'
    fname = os.path.join(self.config['datadir'], fname)
    df.to_csv(fname, index=False)

  #
  #
  #
  def dump_iptables(self):
    if self.verbose:
      log.log('  * {:10s} - dump_iptables : {:d} data items'.format(
        self.profile, len(self.blacklist)))
    chain = self.config['chain']

    Lines = []
    Lines.append('iptables -F {:s}'.format(chain))
    for bl in self.blacklist:
      fmt = "iptables -A {:s} -p tcp -s {:s} -j DROP"
      Lines.append(fmt.format(chain, bl[1]))

    fname = '{:s}-iptables.sh'.format(self.profile)
    fpath = os.path.join(self.config['datadir'], fname)
    try:
      with open(fpath, 'w') as fout:
        fout.write('#! /bin/bash' + '\n\n')
        fout.write('\n'.join(Lines) + '\n')
    except Exception as e:
      log.log('   Exception caught {:}'.format(e))
    finally:
      if os.path.isfile(fpath):
        os.chmod(fpath, 0o755)

    try:
      log.log('  * {:10s} - updating firewall : {:d} data items'.format(
      self.profile, len(self.blacklist)))
      cp = run([fpath])
      #log.log("   Result : {:}".format(cp.returncode))
    except Exception as e:
      log.log('   Exception caught {:}'.format(e))
    finally:
      pass

    return Lines

  #
  #
  #
  def update_blacklist(self):
    now = datetime.now().timestamp()
    expire = float(self.config['expire'])
    wsize = float(self.config['wsize'])
    maxerr = int(self.config['maxerr'])

    bl = {e[1]: e[0] for e in self.blacklist}
    for addr in bl.keys():
      if bl[addr] + wsize < now:
        log.log('* {:10s} - Whitelisting {:s}'.format(self.profile, addr))

    columns = ['date', 'address', 'expr']
    columns = ['date', 'address']
    events = self.events.copy()
    df = pd.DataFrame(events, columns=columns)
    df = df[df['date'] + wsize >= now]
    df['count'] = 1
    dfc = df.groupby('address', as_index=False).count()
    dfc = dfc[dfc['count'] > maxerr]
    self.blacklist.clear()
    for i, r in dfc.iterrows():
      addr = r['address']
      last = df[df['address'] == addr]['date'].max()
      evt = [last, addr]
      self.blacklist.append(evt)
      if not addr in bl.keys():
        log.log('* {:10s} - Blacklisting {:s}'.format(self.profile, addr))

  #
  #
  #
  def runOld(self):
    args = ['/opt/log2fw-tools/bin/jmTail.py']
    args = [self.config.get('tailprog')]
    args += self.logfiles

    pid = None
    try:
      with Popen(args, stdout=PIPE) as proc:
        global childPids
        pid = proc.pid
        childPids.append(pid)
        last = 0
        nevt = 0
        while not exitFlag:
          line = str(proc.stdout.readline(), encoding='utf-8').strip()
          if self.debug:
            print(line)
          events = lines_to_events([line], self.expr, self.regex, self.profile)
          if len(events) > 0:  # 5 ???
            nevt += 1
            self.events.extend(events)
          now = datetime.now().timestamp()
          if nevt >= 5 and last + 600 < now or last + 1200 < now:
          #if True:
            last = now
            nevt = 0
            # update
            self.update_blacklist()
            self.dump_iptables()
            # save
            self.dump_events()
            self.dump_blacklist()
        proc.terminate()
        proc.kill()
    except Exception as e:
      print('Popen exception {:}'.format(e))
    finally:
      # update
      self.update_blacklist()
      self.dump_iptables()
      # save
      self.dump_events()
      self.dump_blacklist()

  #
  #
  #
  def run(self):
    args = ['/opt/log2fw-tools/bin/jmTail.py']
    args = [self.config.get('tailprog')]
    args += self.logfiles

    tout = self.config.getint('dtdump')
    pid = None
    try:
      with Popen(args, stdout=PIPE) as proc:
        global childPids
        pid = proc.pid
        childPids.append(pid)
        last = datetime.now().timestamp()
        nevt = 0
        while not exitFlag:
          (inp, out, err) = select.select([proc.stdout], [], [], tout)
          if self.debug:
            log.log('=> select {:d} {:d} {:d}'.format(len(inp), len(out), len(err)))
          if self.debug and len(inp) == 0:
            log.log('Got a timeout...')

          if len(inp) > 0:
            line = str(proc.stdout.readline(), encoding='utf-8').strip()
            if self.debug:
              print(line)
            events = lines_to_events([line], self.expr, self.regex, self.profile)
            if len(events) > 0:  # 5 ???
              nevt += 1
              self.events.extend(events)

          now = datetime.now().timestamp()
          if (nevt >= 5 and last + 120 < now) or (nevt > 0 and last + tout < now):
            last = now
            nevt = 0
            # update
            self.update_blacklist()
            self.dump_iptables()
            # save
            self.dump_events()
            self.dump_blacklist()
        proc.terminate()
        proc.kill()
    except Exception as e:
      print('Popen exception {:}'.format(e))
    finally:
      # update
      self.update_blacklist()
      self.dump_iptables()
      # save
      self.dump_events()
      self.dump_blacklist()


  #
  #
  #
  def fromfile(self):
    log.log('* Starting fromfile {:s}'.format(self.profile))
    args = sorted(self.logfiles)

    events = []
    for fname in args:
      events.clear()
      try:
        print('  Reading => ', fname)
        with open(fname, 'r') as fin:
          lines = fin.readlines()
          for i in range(0, len(lines)):
            lines[i] = str(lines[i]).strip()
          events += lines_to_events(lines, self.expr, self.regex, self.profile)
        if len(events) > 0:  # 5 ???
          self.events.extend(events)
      except Exception as e:
        print('===> Got an exception ', e)
      finally:
        pass

    if len(self.events) > 0:
      # update
      self.update_blacklist()
      self.dump_iptables()
      # save
      self.dump_events()
      self.dump_blacklist()


# -----------------------------------------------------------------------------
#
# #    #    ##       #    #    #
# ##  ##   #  #      #    ##   #
# # ## #  #    #     #    # #  #
# #    #  ######     #    #  # #
# #    #  #    #     #    #   ##
# #    #  #    #     #    #    #
#
def doProfile(cli, profile, config):
  if profile in config.sections():
    ctx = MonitorContext(cli, profile, config[profile])
    if cli.what == 'monitor':
      ctx.run()
    if cli.what == 'fromfile':
      ctx.fromfile()


#
#
#
class logThread(threading.Thread):
  def __init__(self, tID, cli, profile, config):
    threading.Thread.__init__(self)
    self.tID = tID
    self.profile = profile
    self.name = 'Thread - ' + profile
    self.cli = cli
    self.config = config

  def run(self):
    log.log("* Starting profile " + self.profile)
    doProfile(self.cli, self.profile, self.config)
    log.log("* Exiting profile " + self.profile)


#
#
#
def main(cli, config):
  if cli.what == 'monitor':
    if not cli.profile in config.sections() and cli.profile != 'all':
      log.log(f'Error : profile {cli.profile} not found')
      print(f'Error : profile {cli.profile} not found')
      return 1

  if True:
    atexit.register(killChildren)
  else:
    pass
  if True:
    signal.signal(signal.SIGINT, sigHandler)
    signal.signal(signal.SIGTERM, sigHandler)
    signal.signal(signal.SIGQUIT, sigHandler)

  threads = []
  threadID = 1
  if cli.profile == 'all':
    profiles = config.sections()
  else:
    profiles = [cli.profile]

  # Create new threads
  for profile in profiles:
    thread = logThread(threadID, cli, profile, config)
    thread.start()
    threads.append(thread)
    threadID += 1

  for t in threads:
    #continue
    # the following does not work because of lock problems.
    t.join()

  log.log("* Exiting Main Thread")

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

  parser.add_argument('--what',
                      help='What to do (monitor)',
                      default='monitor',
                      type=str)
  parser.add_argument('--showconf', help='', action="store_true")
  parser.add_argument('--showargs', help='', action="store_true")

  parser.add_argument('--dir',
                      help='',
                      default='/var/lib/auth-monitor',
                      type=str)
  parser.add_argument('--dout',
                      help='Output directory',
                      default='tmp',
                      type=str)
  parser.add_argument('--profile', help='', default=None, type=str)
  parser.add_argument('--reset', help='', action="store_true")

  #parser.add_argument('--int', default=None, help='PID to monitor', type=int)
  #parser.add_argument('--str', default="String", help='A string', type=str)

  cli = parser.parse_args()
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

  log = jmSyslog.JmLog("log2fw")
  log.log(f"* Started at {time.strftime('%X')}")

  cli = getCliArgs()

  bAppl = os.path.basename(sys.argv[0])
  bConf = bAppl.replace('.py', '.conf')
  #bConf = 'fw-tools.conf'
  bDir = '/opt/log2fw-tools/etc'
  fConfig = os.path.join(bDir, bConf)
  config = None
  if os.path.isfile(fConfig):
    config = appLoadConfigFile(fConfig)

  if True:
    if cli.showconf:
      appShowConfigFile(config)
    if cli.showargs:
      showArgs(cli, True)
    if cli.showconf or cli.showargs:
      sys.exit(0)

  sys.exit(main(cli, config))
