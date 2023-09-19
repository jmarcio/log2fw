#! /usr/bin/env python3

import sys
import os
import syslog
import signal
import asyncio
import time
import random

#
#
#
def sigHandler(signum, frame):
    print('* Signal handler called with signal', signum)
    exit(0)

#
#
#
class Context:
  def __init__(self, config=None):
    self.data = []
    self.events = []
    self.blacklist = []

    self.tasks = []
    self.cons = None

    self.debug  = False
    self.verbose = False

    self.config = config

    self.log_facility = syslog.LOG_USER

  def addData(self, v=None):
    if not v is None:
      self.data.append(v)

  def dumpData(self):
    print(f'  Dumping {len(self.data):d} data items')
    for i in range(0, len(self.data)):
      print('    {:3d}'.format(self.data[i]))
    self.data.clear()

  def terminate(self):
    pass

  def setDebug(self, debug):
    self.debug = debug

  def setVerbose(self, verbose):
    self.verbose = verbose



#
#
#
async def producer(ctx, rank=1):
  while True:
    r = random.randint(0,100)
    ctx.addData(r)

    dt = random.randint(1,10)
    print(f'* {rank:2d} : Will sleep {dt:2d} s : {r:3d}')
    await asyncio.sleep(dt)

#
#
#
async def consummer(ctx):
  while True:
    print('* Consumer : {:d} data items'.format(len(ctx.data)))
    ctx.dumpData()
    await asyncio.sleep(20)


#
#
#
async def main(ctx):
  data = []
  tasks = []
  for i in range(1, 8):
    t = asyncio.create_task(producer(ctx, i))
    ctx.tasks.append(t)

  ctx.cons = asyncio.create_task(consummer(ctx))
  time.sleep(1)
  print('{:d} tasks'.format(len(tasks)))
  print(f"  started at {time.strftime('%X')}")
  for i in range(0, len(ctx.tasks)):
    print('   ', i)
    await ctx.tasks[i]
  await ctx.cons

  print(f"  Stopped at {time.strftime('%X')}")

#
#
#
ctx = Context()

signal.signal(signal.SIGINT, sigHandler)
signal.signal(signal.SIGTERM, sigHandler)
signal.signal(signal.SIGQUIT, sigHandler)
##signal.signal(signal.SIGKILL, sigHandler)

try:
  asyncio.run(main(ctx))
except:
  print(f"* Exception at {time.strftime('%X')}")
finally:
  print(f"* Finally at {time.strftime('%X')}")
  ctx.dumpData()
  ctx.terminate()
  print(f"* Finally at {time.strftime('%X')}")
