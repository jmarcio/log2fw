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
import signal
import asyncio
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
    #line = bytes(line, encoding='utf8')
    expr.append(line)

  re_lines = cfProfile['regex']
  regex = []
  for line in re_lines.split('\n'):
    line = line.strip()
    if line == '':
      continue
    #line = bytes(line, encoding='utf8')
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


#
#
#
def sigHandler(signum, frame):
  print('* Signal handler called with signal', signum)
  exit(0)


# -----------------------------------------------------------------------------
#
# #    #  #    #   ####   #    #    ##       #    #    #
# ##  ##  #   #   #    #  #    #   #  #      #    ##   #
# # ## #  ####    #       ######  #    #     #    # #  #
# #    #  #  #    #       #    #  ######     #    #  # #
# #    #  #   #   #    #  #    #  #    #     #    #   ##
# #    #  #    #   ####   #    #  #    #     #    #    #
#
def mkChain(profile, chain='AuthSSH', wdir='/var/lib/auth-monitor'):
  fIn = '{:s}-listed.csv'.format(profile)
  fIn = os.path.join(wdir, fIn)
  df = pd.read_csv(fIn)
  df['block'] = df['date'] + df['length'] > 1691412336 + 400000
  df['block'] = df['date'] + df['length'] > time.time() + 86400 * 6
  dfbl = df[df['block'] > 0]

  Lines = []
  Lines.append('iptables -F {:s}'.format(chain))
  for ip in dfbl['address']:
    fmt = "iptables -A {:s} -p tcp -s {:s} -j DROP"
    Lines.append(fmt.format(chain, ip))
  return Lines


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
    log.log(f"* MonitorContext init at {time.strftime('%X')}")
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
    self.log_lock = asyncio.Lock()
    self.events = []
    self.evt_lock = asyncio.Lock()
    self.blacklist = []
    self.bl_lock = asyncio.Lock()
    self.lock = asyncio.Lock()
    self.need_update = False

    self.df_events = None
    self.last_read_event = 0
    self.df_blacklist = None

    self.read_events()
    self.read_blacklist()

    self.expr, self.regex = decode_conf_str_matches(self.config)
    if self.debug:
      log.log('* Expr : {:d} - Regex : {:d}'.format(len(self.expr),
                                                    len(self.regex)))

  def _df_to_list(self, df):
    llist = []
    for i, row in df.iterrows():
      e = []
      for c in df.columns:
        e.append(row[c])
      llist.append(e)
    return llist

  def read_events(self):
    log.log('  * read_events')

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

  def read_blacklist(self):
    log.log('  * read_blacklist')

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

  def dump_events(self):

    #nb = len(df_events['date'])
    #log.log('  * dump_events    : {:d} data items'.format(nb))
    log.log('  * dump_events    : {:d} data items'.format(len(self.events)))

    #async with self.lock:
    if True:
      fname = f'{self.profile:s}-events.csv'
      fname = os.path.join(self.config['datadir'], fname)
      self.df_events.to_csv(fname, index=False)
    else:
      columns = ['date', 'address', 'expr']
      columns = ['date', 'address']
      events = self.events.copy()
      df = pd.DataFrame(events, columns=columns)
      if 'expr' in columns:
        del df['expr']
      fname = f'{self.profile:s}-events.csv'
      fname = os.path.join(self.config['datadir'], fname)
      #log.log('    fname = ', fname)
      df.to_csv(fname, index=False)

  def dump_blacklist(self):

    #nb = len(df_events['date'])
    #log.log('  * dump_blacklist : {:d} data items'.format(nb))
    log.log('  * dump_blacklist : {:d} data items'.format(len(self.blacklist)))

    #async with self.lock:
    if True:
      fname = f'{self.profile:s}-blacklist.csv'
      fname = os.path.join(self.config['datadir'], fname)
      self.df_blacklist.to_csv(fname, index=False)
    else:
      columns = ['date', 'address', 'count']
      columns = ['date', 'address']
      blacklist = self.blacklist.copy()
      df = pd.DataFrame(blacklist, columns=columns)
      fname = f'{self.profile:s}-blacklist.csv'
      fname = os.path.join(self.config['datadir'], fname)
      #log.log('    fname = ', fname)
      df.to_csv(fname, index=False)

  def update_blacklist(self):
    pass


#
#
#
async def handle_logfile(ctx, fname):
  log.log('* {:8s} handle_logfile   : {:s} - {:d} lines'.format(
    ctx.profile, fname, len(ctx.loglines)))
  async for line in jmTail.Tail(fname, fp_poll_secs=5):
    #log.log('* {:8s} handle_logfile   : {:d} lines'.format(
    #  ctx.profile, len(ctx.loglines)))
    if True:
      async with ctx.lock:
        ctx.loglines.append(line)
    if ctx.debug:
      log.log(line)


#
#
#
async def handle_loglines(ctx):
  fmt = '* {:8s} handle_loglines  : {:d} log lines'
  while True:
    log.log(fmt.format(ctx.profile, len(ctx.loglines)))
    async with ctx.lock:
    #if True:
      if len(ctx.loglines) > 0:
        lines = ctx.loglines
        events = lines_to_events(lines, ctx.expr, ctx.regex, ctx.profile)
        if True:
          #async with ctx.lock_events:
          if True:
            ctx.events.extend(events)
          if ctx.debug:
            for evt in events:
              print('  ', evt)
        else:
          for evt in events:
            #log.log(f'   date : {evt[0]} {self.last_read_event}')
            #if evt[0] <= self.last_read_event:
            #  continue
            if True:
              #async with  ctx.lock_events:
              ctx.events.append(evt)
            #if ctx.verbose:
            #  print("  ", evt)
        ctx.loglines.clear()
    await asyncio.sleep(10)


#
#
#
async def handle_events(ctx):
  prevEvents = 0
  fmt = '* {:8s} handle_events    : {:d} events - new : {:d}'
  while True:
    new_events = len(ctx.events) - prevEvents
    log.log(fmt.format(ctx.profile, len(ctx.events), new_events))
    if len(ctx.events) > prevEvents:
      #new_events = ctx.events[prevEvents:len(ctx.events)]
      #df = pd.DataFrame(new_events, columns=ctx.df_events.columns)
      for i in range(prevEvents, len(ctx.events)):
        e = ctx.events[i]
        if ctx.verbose:
          log.log(f"  Event : {e}")

      prevEvents = len(ctx.events)

    await asyncio.sleep(10)



#
#
#
async def dump_data(ctx):
  fmt = '* {:8s} dump_data'
  while True:
    log.log(fmt.format(ctx.profile))

    if False:
      ctx.dump_events()
      ctx.dump_blacklist()

    if True:
      log.log('  * dump_events    : {:d} data items'.format(len(ctx.events)))
      columns = ['date', 'address', 'expr']
      columns = ['date', 'address']
      async with ctx.lock:
        events = ctx.events.copy()
      df = pd.DataFrame(events, columns=columns)
      if 'expr' in columns:
        del df['expr']
      fname = f'{ctx.profile:s}-events.csv'
      fname = os.path.join(ctx.config['datadir'], fname)
      #log.log('    fname = ', fname)
      df.to_csv(fname, index=False)

      log.log('  * dump_blacklist : {:d} data items'.format(len(ctx.blacklist)))
      columns = ['date', 'address', 'count']
      columns = ['date', 'address']
      async with ctx.lock:
        blacklist = ctx.blacklist.copy()
      df = pd.DataFrame(blacklist, columns=columns)
      fname = f'{ctx.profile:s}-blacklist.csv'
      fname = os.path.join(ctx.config['datadir'], fname)
      #log.log('    fname = ', fname)
      df.to_csv(fname, index=False)

    await asyncio.sleep(180)



#
#
#
async def update_blacklist(ctx):

  while True:
    fmt = '* {:8s} update_blacklist - start'
    log.log(fmt.format(ctx.profile))

    now = datetime.now().timestamp()
    expire = float(ctx.config['expire'])
    wsize = float(ctx.config['wsize'])
    marge = 600

    blacklist = {}
    need_update = False
    events = {}

    async with ctx.lock:
      for evt in ctx.blacklist:
        if evt[0] + wsize + marge < now:
          log.log(f' * {ctx.profile:10s} Whitelisting {evt[1]}')
          need_update = True
        else:
          blacklist[evt[1]] = evt[0]

    async with ctx.lock:
      for evt in ctx.events:
        if evt[0] + wsize + marge < now:
          continue
        if not evt[1] in events:
          events[evt[1]] = [evt[0]]
        else:
          events[evt[1]].append(evt[0])

    maxerr = int(ctx.config['maxerr'])
    for k in events.keys():
      if not k in blacklist.keys() and len(events[k]) > maxerr:
        log.log(f' * {ctx.profile:10s} Blacklisting {k}')
        need_update = True
        blacklist[k] = max(events[k])

    bl = [[blacklist[k], k] for k in blacklist.keys()]

    async with ctx.lock:
      ctx.blacklist.clear()
      ctx.blacklist.extend(bl)
      ctx.need_update = need_update

    fmt = '* {:8s} update_blacklist - end'
    log.log(fmt.format(ctx.profile))

    await asyncio.sleep(120)

#
#
#
async def mainMonitor(cli, ctx):

  log.log(f"* mainMonitor at {time.strftime('%X')}")

  for fname in ctx.logfiles:
    t = asyncio.create_task(handle_logfile(ctx, fname))
    ctx.tasks_log.append(t)
  ctx.task_lines = asyncio.create_task(handle_loglines(ctx))
  ctx.task_events = asyncio.create_task(handle_events(ctx))
  ctx.task_dump = asyncio.create_task(dump_data(ctx))
  ctx.task_blacklist = asyncio.create_task(update_blacklist(ctx))

  for i in range(0, len(ctx.tasks_log)):
    await ctx.tasks_log[i]
  await ctx.task_lines
  await ctx.task_events
  await ctx.task_dump
  await ctx.update_blacklist

  return 0


# -----------------------------------------------------------------------------
#
# #    #    ##       #    #    #
# ##  ##   #  #      #    ##   #
# # ## #  #    #     #    # #  #
# #    #  ######     #    #  # #
# #    #  #    #     #    #   ##
# #    #  #    #     #    #    #
#
def asyncio_main(cli, config):
  #
  #
  #
  if cli.what == 'monitor':
    if not cli.profile in config.sections():
      log.log(f'Error : profile {cli.profile} not found')
      print(f'Error : profile {cli.profile} not found')
      return 1

    signal.signal(signal.SIGINT, sigHandler)
    signal.signal(signal.SIGTERM, sigHandler)
    signal.signal(signal.SIGQUIT, sigHandler)

    ctx = MonitorContext(cli, cli.profile, config[cli.profile])

    #result = asyncio.run(mainMonitor(cli, ctx), debug=True)
    result = 0
    try:
      log.log(f"* Will try mainMonitor at {time.strftime('%X')}")
      result = asyncio.run(mainMonitor(cli, ctx), debug=True)
    except Exception as e:
      log.log(f"* Exception at {time.strftime('%X')}")
      log.log(f'caught {type(e)}: e')
    finally:
      log.log(f"* Finally at {time.strftime('%X')}")
      #ctx.dump_events()
      #ctx.dump_blacklist()
      #ctx.terminate()
      log.log(f"* Finally at {time.strftime('%X')}")

      #return async mainMonitor(cli, config)
    return result

  #
  #
  #
  return 1

def main(cli, config):
  sproc = ['/opt/log2fw-tools/bin/jmTail.py']
  for p in sproc:
    print('  {:}'.format(p))
  try:
    with sp.Popen(sproc, stdout=sp.PIPE) as proc:
      print('Popen ok')
      while True:
        line = str(proc.stdout.readline(), encoding='utf-8').strip()
        print(line)
  except:
    print('Popen error')

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

  parser.add_argument('--dir',
                      help='',
                      default='/var/lib/auth-monitor',
                      type=str)
  parser.add_argument('--dout',
                      help='Output directory',
                      default='tmp',
                      type=str)
  parser.add_argument('--profile', help='', default=None, type=str)

  #parser.add_argument('--int', default=None, help='PID to monitor', type=int)
  #parser.add_argument('--str', default="String", help='A string', type=str)

  cli = parser.parse_args()
  return cli


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
    #if cli.showargs:
    #  showArgs(cli, True)
    #if cli.showconf or cli.showargs:
    if cli.showconf:
      sys.exit(0)

  sys.exit(main(cli, config))
