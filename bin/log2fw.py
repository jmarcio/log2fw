#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  log2fw.py
#
#  Copyright 2023 José Marcio Martins da Cruz <martins@jose-marcio.org>
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the  nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#  Description :
#
#  History :
#     20/09/2023 - Initial release
#

import os
import sys
import select

import signal
import atexit
import subprocess as sp
import threading

import time

import glob

import re
from datetime import datetime

import argparse as ap
import configparser as cp
import jmSyslog
from jmVersion import VersionStr

import numpy as np
import pandas as pd


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
  #log.log('killChildren')
  global exitFlag
  exitFlag = True
  for pid in childPids:
    #print('===> Killing ', pid)
    try:
      os.kill(pid, signal.SIGTERM)
    except Exception as e:
      print(f'Exception when killing child process {pid:} : {e:}')


def sigHandler(signum, frame):
  #log.log('Signal handler called with signal', signum)
  global exitFlag
  exitFlag = True
  killChildren()
  #exit(0)


#
#
#
def now():
  return datetime.now().timestamp()


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
    log.log(f"MonitorContext init {profile:s} at {time.strftime('%X')}")
    self.profile = profile
    self.config = config

    self.cli = cli
    self.debug = cli.debug
    self.verbose = cli.verbose

    #
    self.logfiles = []
    cfFiles = config['logfile'].replace('\n', ' ').split(' ')
    cfFiles = [f for f in cfFiles if f != '']
    lFiles = []
    for f in cfFiles:
      lFiles += glob.glob(f)
    self.logfiles = lFiles

    #
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

    self.substr, self.regex = self.decodeConfigStrMatches(self.config)
    if self.verbose:
      log.log('{:10s} - Substr : {:d} - Regex : {:d}'.format(
        self.profile, len(self.substr), len(self.regex)))
    log.log('{:10s} - Logfiles :'.format(self.profile))
    for f in self.logfiles:
      log.log('  {:10s} - {:s}'.format(self.profile, f))

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
  # #####   ######    ##    #####           #####   #    #  #    #  #####
  # #    #  #        #  #   #    #          #    #  #    #  ##  ##  #    #
  # #    #  #####   #    #  #    #  #####   #    #  #    #  # ## #  #    #
  # #####   #       ######  #    #          #    #  #    #  #    #  #####
  # #   #   #       #    #  #    #          #    #  #    #  #    #  #
  # #    #  ######  #    #  #####           #####    ####   #    #  #
  #
  def read_events(self):
    log.log('{:10s} - read_events'.format(self.profile))

    fname = f'{self.profile:s}-events.csv'
    fname = os.path.join(self.config['datadir'], fname)
    columns = ['date', 'address']
    if os.path.isfile(fname):
      df = pd.read_csv(fname)
      for c in df.columns:
        if not c in columns:
          del df[c]
      now = datetime.now().timestamp()
      expire = self.config.getfloat('expire')
      #wsize = self.config.getfloat('wsize')
      self.df_events = df[df['date'] + expire > now].copy()
    else:
      self.df_events = pd.DataFrame([], columns=columns)
    self.events = self._df_to_list(self.df_events)

  #
  #
  def read_blacklist(self):
    log.log('{:10s} - read_blacklist'.format(self.profile))

    fname = f'{self.profile:s}-blacklist.csv'
    fname = os.path.join(self.config['datadir'], fname)
    columns = ['date', 'address']
    if os.path.isfile(fname):
      df = pd.read_csv(fname)
      for c in df.columns:
        if not c in columns:
          del df[c]
      now = datetime.now().timestamp()
      expire = self.config.getfloat('expire')
      #wsize = self.config.getfloat('wsize')
      self.df_blacklist = df[df['date'] + expire > now].copy()
    else:
      self.df_blacklist = pd.DataFrame([], columns=columns)
    self.blacklist = self._df_to_list(self.df_blacklist)

  #
  #
  def dump_events(self):
    if self.verbose:
      log.log('{:10s} - dump_events    : {:d} data items'.format(
        self.profile, len(self.events)))

    columns = ['date', 'address', 'substr']
    columns = ['date', 'address']
    events = self.events.copy()
    df = pd.DataFrame(events, columns=columns)
    if 'substr' in columns:
      del df['substr']
    fname = f'{self.profile:s}-events.csv'
    fname = os.path.join(self.config['datadir'], fname)
    df.to_csv(fname, index=False)

  #
  #
  #
  def dump_blacklist(self):
    if self.verbose:
      log.log('{:10s} - dump_blacklist : {:d} data items'.format(
        self.profile, len(self.blacklist)))

    columns = ['date', 'address', 'count']
    columns = ['date', 'address']
    blacklist = self.blacklist.copy()
    df = pd.DataFrame(blacklist, columns=columns)
    fname = f'{self.profile:s}-blacklist.csv'
    fname = os.path.join(self.config['datadir'], fname)
    df.to_csv(fname, index=False)

  #
  # #    #  #####   #####     ##     #####  ######
  # #    #  #    #  #    #   #  #      #    #
  # #    #  #    #  #    #  #    #     #    #####
  # #    #  #####   #    #  ######     #    #
  # #    #  #       #    #  #    #     #    #
  #  ####   #       #####   #    #     #    ######
  #
  def dump_iptables(self):
    if self.verbose:
      log.log('{:10s} - dump_iptables : {:d} data items'.format(
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

    if os.geteuid() == 0:
      try:
        log.log('{:10s} - updating firewall : {:d} data items'.format(
          self.profile, len(self.blacklist)))
        cp = sp.run([fpath])
        if self.debug:
          log.log("   Result : {:}".format(cp.returncode))
      except Exception as e:
        log.log('   Exception caught {:}'.format(e))
      finally:
        pass
    else:
      log.log('Only root can update iptables rules')

    return Lines

  #
  #
  #
  def update_blacklist(self):
    if self.verbose:
      log.log('{:10s} - updating blacklist'.format(self.profile))
    now = datetime.now().timestamp()
    #expire = self.config.getfloat('expire')
    wsize = self.config.getfloat('wsize')
    maxerr = self.config.getint('maxerr')

    bl = {e[1]: e[0] for e in self.blacklist}
    for addr in bl.keys():
      if bl[addr] + wsize < now:
        log.log('{:10s} - Whitelisting {:s}'.format(self.profile, addr))

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
        log.log('{:10s} - Blacklisting {:s}'.format(self.profile, addr))

  #
  #      #   ####   #####
  #      #  #    #  #    #
  #      #  #    #  #####
  #      #  #    #  #    #
  # #    #  #    #  #    #
  #  ####    ####   #####
  #
  def monitor(self):
    #
    #
    #
    def needUpdate(last, now, newevts, dtdump):
      if (newevts >= 5 and last + 120 < now):
        return True
      if (newevts > 0 and last + dtdump < now):
        return True
      if last + 3600 < now:
        return True
      return False

    #
    # main
    #
    args = [self.config.get('tailprog')]
    args += self.logfiles

    dtdump = self.config.getint('dtdump')
    pid = None
    try:
      with sp.Popen(args, stdout=sp.PIPE) as proc:
        global childPids
        pid = proc.pid
        childPids.append(pid)
        last = datetime.now().timestamp()
        newevts = 0
        while not exitFlag:
          (inp, out, err) = select.select([proc.stdout], [], [], dtdump)
          if self.debug and len(inp) == 0:
            log.log('   Got a timeout...')

          if len(inp) > 0:
            line = str(proc.stdout.readline(), encoding='utf-8').strip()
            if self.debug:
              print(line)
            events = self.lines2events([line], self.substr, self.regex,
                                       self.profile)
            if len(events) > 0:  # 5 ???
              newevts += 1
              self.events.extend(events)

          now = datetime.now().timestamp()
          if needUpdate(last, now, newevts, dtdump):
            last = now
            newevts = 0
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
    log.log('Starting fromfile {:s}'.format(self.profile))
    if not cli.logfile is None:
      if not os.path.isfile(cli.logfile):
        return 1
      args = [cli.logfile]
    else:
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
          events += self.lines2events(lines, self.substr, self.regex,
                                      self.profile)
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

    return 0

  #
  # #####   ####    ####   #        ####
  #   #    #    #  #    #  #       #
  #   #    #    #  #    #  #        ####
  #   #    #    #  #    #  #            #
  #   #    #    #  #    #  #       #    #
  #   #     ####    ####   ######   ####
  #
  def lines2events(self, lines, substr=[], regex=[], profile='apache'):
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
      line = line.lower()
      for r in substr:
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
        if not re.search(r, line, flags=re.IGNORECASE) is None:
          #line = line.decode('utf8')
          tstamp = getDate(line, profile)
          ip = getIPAddress(line)
          if not ip is None:
            evt = [tstamp, ip, r]
            evt = [tstamp, ip]
            events.append(evt)
          break

    return events

  #
  #
  #
  def decodeConfigStrMatches(self, cfProfile):
    substr = []
    regex = []

    # sub strings
    substr = []
    fpath = os.path.join(self.cli.cfdir, f'{self.profile:s}-substr.txt')
    if os.path.isfile(fpath):
      with open(fpath, 'r') as fin:
        for line in fin.readlines():
          line = line.strip()
          if line != '' and not line.startswith('#'):
            substr.append(line)

    substr_lines = cfProfile['substr']
    for line in substr_lines.split('\n'):
      line = line.strip()
      if line == '' or line == '__none__':
        continue
      substr.append(line.lower())

    if self.debug:
      for sstr in substr:
        log.log('  substr ' + sstr)

    # regex
    fpath = os.path.join(self.cli.cfdir, f'{self.profile:s}-regex.txt')
    if os.path.isfile(fpath):
      with open(fpath, 'r') as fin:
        for line in fin.readlines():
          line = line.strip()
          if line != '' and not line.startswith('#'):
            regex.append(line)

    re_lines = cfProfile['regex']
    for line in re_lines.split('\n'):
      line = line.strip()
      if line == '' or line == '__none__':
        continue
      regex.append(line)

    if self.debug:
      for rexpr in regex:
        log.log('  regex  ' + rexpr)

    return substr, regex


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
      ctx.monitor()
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
    log.log("Starting profile " + self.profile)
    doProfile(self.cli, self.profile, self.config)
    log.log("Exiting profile " + self.profile)


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
    if not config.getboolean(profile, 'enabled'):
      continue
    thread = logThread(threadID, cli, profile, config)
    thread.start()
    threads.append(thread)
    threadID += 1

  for t in threads:
    t.join()

  log.log("Exiting Main Thread")

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
  parser.add_argument('--version',
                      help='Show version and exits',
                      action="store_true")

  parser.add_argument('--conf',
                      help='Configuration file if not the default one',
                      default=None,
                      type=str)

  parser.add_argument('--what',
                      help='What to do (monitor|fromfile)',
                      default='monitor',
                      type=str)
  parser.add_argument(
    '--logfile',
    help='Use only with a specific profile and what=fromfile',
    default=None,
    type=str)
  parser.add_argument('--showconf',
                      help='Show configuration file contents',
                      action="store_true")
  parser.add_argument('--showargs',
                      help='Show cli options',
                      action="store_true")

  parser.add_argument('--profile',
                      help='Profile to monitor or all',
                      default='all',
                      type=str)
  parser.add_argument('--reset',
                      help='Clear previous events and blacklist data',
                      action="store_true")

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

  log = jmSyslog.JmLog("log2fw")
  log.log(f"{VersionStr():s} - Started at {time.strftime('%X')}")

  cli = getCliArgs()
  if cli.version:
    print(VersionStr())
    sys.exit(0)

  config = None
  if cli.conf is None:
    bConf = os.path.basename(sys.argv[0]).replace('.py', '.conf')
    confDirs = ['/etc/log2fw', '/opt/log2fw/etc']
    for bDir in confDirs:
      fConfig = os.path.join(bDir, bConf)
      if os.path.isfile(fConfig):
        config = appLoadConfigFile(fConfig)
        log.log(f'Using configuration file {fConfig:}')
        cli.conf = fConfig
        break
  else:
    bConf = cli.conf
    if os.path.isfile(cli.conf):
      config = appLoadConfigFile(cli.conf)
      log.log(f'Using configuration file {cli.conf:}')

  if config is None:
    msg = f'===> Configuration file {bConf:} not found'
    print(msg)
    sys.exit(1)

  cli.cfdir = os.path.dirname(cli.conf)

  if cli.showconf:
    appShowConfigFile(config)
  if cli.showargs:
    showArgs(cli, True)
  if cli.showconf or cli.showargs:
    sys.exit(0)

  sys.exit(main(cli, config))
