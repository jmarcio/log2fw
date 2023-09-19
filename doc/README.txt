
https://docs.python.org/fr/3/library/subprocess.html

import subprocess as sp

with sp.Popen(["/usr/bin/tail", "-f", "/var/log/syslog"], stdout=sp.PIPE) as proc:
  while True:
    line = str(proc.stdout.readline(), encoding='utf-8').strip()
    print(line)

*****************


https://docs.python.org/3/library/socket.html

https://pythontic.com/modules/socket/socketpair

https://www.programcreek.com/python/example/4043/socket.socketpair

https://programtalk.com/python-examples/socket.socketpair/?utm_content=cmp-true


**********************

https://docs.python.org/3/library/threading.html



