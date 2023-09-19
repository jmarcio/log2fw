#! /usr/bin/env python3
# -*- coding: utf-8 -*-
#
# >>
#   Blake VandeMerwe, LiveViewTech
# <<

import os
import sys
import io
import glob
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

  #
  #
  #
  async def readlog(fname):
    #print('{:s} starting readlog : {:}'.format('-' * 15, fname))
    try:
      async for line in Tail(fname , fp_poll_secs=5):
        if os.getppid() == 1:
          break
        sys.stdout.write(line + '\n')
        sys.stdout.flush()
    except Exception as e:
      pass
    finally:
      pass

  async def mainWargs(argv=sys.argv):
    #print(argv)
    args = argv.copy()
    del args[0]

    files = []
    for f in args:
      fl = glob.glob(f)
      for fg in fl:
        if os.path.isfile(fg):
          files.append(fg)
        else:
          print("File {fb:} doesn't exists")
    if len(files) == 0:
      print('No file found')
      return 1

    tasks = []
    for f in files:
      t = asyncio.create_task(readlog(f))
      tasks.append(t)

    for t in tasks:
      await t
    return 0

    for i in range(0, len(tasks)):
      await tasks[i]
    return 0

  #
  #
  #
  try:
    asyncio.run(mainWargs(sys.argv))
  except KeyboardInterrupt:
    pass
  except Exception as e:
    pass
  finally:
    pass

  exit(0)

