#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#
#
import os
import sys
import subprocess as sp




def main(args):
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

if __name__ == '__main__':
  sys.exit(main(sys.argv))
