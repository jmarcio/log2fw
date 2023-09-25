#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  jmSyslog.py
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

import sys
import syslog


class JmLog:
  facilities = {
    "auth": syslog.LOG_AUTH,
    "authpriv": syslog.LOG_AUTHPRIV,
    "cron": syslog.LOG_CRON,
    "daemon": syslog.LOG_DAEMON,
    "kern": syslog.LOG_KERN,
    "local0": syslog.LOG_LOCAL0,
    "local1": syslog.LOG_LOCAL1,
    "local2": syslog.LOG_LOCAL2,
    "local3": syslog.LOG_LOCAL3,
    "local4": syslog.LOG_LOCAL4,
    "local5": syslog.LOG_LOCAL5,
    "local6": syslog.LOG_LOCAL6,
    "local7": syslog.LOG_LOCAL7,
    "lpr": syslog.LOG_LPR,
    "mail": syslog.LOG_MAIL,
    "news": syslog.LOG_NEWS,
    "syslog": syslog.LOG_SYSLOG,
    "user": syslog.LOG_USER,
    "uucp": syslog.LOG_UUCP,
  }

  priorities = {
    "alert": syslog.LOG_ALERT,
    "crit": syslog.LOG_CRIT,
    "debug": syslog.LOG_DEBUG,
    "emerg": syslog.LOG_EMERG,
    "err": syslog.LOG_ERR,
    "info": syslog.LOG_INFO,
    "notice": syslog.LOG_NOTICE,
    "warning": syslog.LOG_WARNING,
  }

  priorityToValues = {
    'debug': syslog.LOG_DEBUG,
    'info': syslog.LOG_INFO,
    'warning': syslog.LOG_WARNING,
    'error': syslog.LOG_ERR
  }

  options = {
    "pid": syslog.LOG_PID,
    "cons": syslog.LOG_CONS,
    "ndelay": syslog.LOG_NDELAY,
    "odelay": syslog.LOG_ODELAY,
    "nowait": syslog.LOG_NOWAIT,
    "perror": syslog.LOG_PERROR,
  }

  facility = syslog.LOG_LOCAL3
  priority = syslog.LOG_INFO

  def __init__(self, ident=sys.argv[0], facility="local3"):
    if facility in self.facilities.keys():
      self.facility = self.facilities[facility]
    syslog.openlog(ident, logoption=syslog.LOG_PID, facility=self.facility)

  def log(self, line, priority='info'):
    if priority in self.priorities.keys():
      pri = self.priorities[priority]
    else:
      pri = self.priority
    syslog.syslog(pri, line)


def main(args):
  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv))
