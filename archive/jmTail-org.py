#! /usr/bin/env python3
# -*- coding: utf-8 -*-
#
# >>
#   Blake VandeMerwe, LiveViewTech
# <<

import os
import sys
import io
import asyncio
import time
from functools import partial
from typing import AsyncIterator

LINE_BUFFER = 1


async def Tail(filename: str,
               last_lines: int = 10,
               non_exist_max_secs: float = 30.0,
               fp_poll_secs: float = 0.125) -> AsyncIterator[str]:
  """Continuously tail a file pointer yielding one line at a time."""
  async def wait_exists() -> bool:
    """Wait for a file to exist, the return statement reflects
        whether or not the file existed when the timeout limits were reached."""
    bail_at: float = time.monotonic() + non_exist_max_secs
    while not os.path.exists(filename):
      if time.monotonic() >= bail_at:
        return False
      await asyncio.sleep(fp_poll_secs)
    return True

  async def check_rotate(_fp) -> io.TextIOBase:
    """Determine if the file rotated in place; same name different inode."""
    nonlocal fino
    if os.stat(filename).st_ino != fino:
      new_fp = open(filename, 'r')
      _fp.close()
      new_fp.seek(0, os.SEEK_SET)
      fino = os.fstat(new_fp.fileno()).st_ino
      return new_fp
    return _fp

  # ~~
  if not await wait_exists():
    return

  buff = io.StringIO()
  stat = os.stat(filename)

  fino: int = stat.st_ino
  size: int = stat.st_size
  blocksize: int = os.statvfs(filename).f_bsize

  fp = open(filename, 'r', LINE_BUFFER)

  if last_lines > 0:
    if stat.st_size <= blocksize:
      # if the file is smaller than 8kb, read all the lines
      for line in fp.readlines()[-last_lines::]:
        yield line.rstrip()
    else:
      # if the file is larger than 8kb, seek 8kb from the end
      #  and return all the lines except the (potential) half-line
      # first element and the null-terminated extra line at the end.
      fp.seek(os.stat(fp.fileno()).st_size - blocksize)
      for line in fp.readlines()[1:-1][-last_lines::]:
        yield line.rstrip()

  # seek to the end of the file for tailing
  #  given the above operations we should already be there.
  fp.seek(0, os.SEEK_END)

  try:
    while True:
      # wait for the file to exist -- generously
      if not os.path.exists(filename):
        if not await wait_exists():
          return

      fp = await check_rotate(fp)
      n_stat = os.fstat(fp.fileno())
      n_size = n_stat.st_size

      # if the file is the same size, churn
      #  .. this could be error-prone on small files that
      # rotate VERY fast, but that's an edge case for
      #  tailing a persistent log file.
      if n_size == size:
        await asyncio.sleep(fp_poll_secs)
        continue

      # if the file shrank, seek to the beginning
      if n_size < size:
        fp.seek(0, os.SEEK_SET)

      size = n_size
      for chunk in iter(partial(fp.read, blocksize), ''):
        buff.write(chunk)

      buff.seek(0, os.SEEK_SET)

      for line in buff.readlines():
        yield line.rstrip()

      # resize our string buffer
      buff.truncate(0)

  except IOError:
    buff.close()
    fp.close()


if __name__ == '__main__':

  fnameD = r'/etc/foldingathome/log.txt'
  fnameA = '/var/log/mail/mail.log'
  fnameB = '/var/log/syslog'
  fnameC = '/var/log/auth-monitor/auth-monitor.log'

  async def readlog(fname):
    print('starting readlog')
    async for line in Tail(fname , fp_poll_secs=5):
      sys.stdout.write(line + '\n')
      sys.stdout.flush()

  async def main2():
    L = await asyncio.gather(
      readlog(fnameA),
      readlog(fnameB),
      readlog(fnameC)
    )
    async with asyncio.TaskGroup() as tg:
        task1 = tg.create_task(readlog(fnameA))
        task2 = tg.create_task(readlog(fnameB))
    print("Both tasks have completed now.")

  async def main(fname='/var/log/syslog'):
    async for line in Tail(fname , fp_poll_secs=5):
      print(line)

  fnameD = r'/etc/foldingathome/log.txt'
  fnameA = '/var/log/mail/mail.log'
  fnameB = '/var/log/apache2/access.log'
  fnameC = '/var/log/auth-monitor/auth-monitor.log'

  #asyncio.run( main())

  print('Launching readlog')
  asyncio.run(readlog('/var/log/syslog'))
  exit(0)

  try:
    #loop = asyncio.get_event_loop()
    #loop.run_until_complete(main())
    asyncio.run(main(fnameA))
  except KeyboardInterrupt:
    pass
  #loop.stop()
  #loop.close()
