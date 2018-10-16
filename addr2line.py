# Depends on eu-addr2line
# Copyright (C) Xilinx Inc.
# Written by Edgar E. Iglesias
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA. 
#

import os
import sys
import string
import subprocess

class addr2line(object):
	def __init__(self, elf, comp_dir = None, addr2line = "addr2line"):
		cmd = [addr2line, "-f", "-e", elf]
#		if comp_dir == None:
#			cmd += ['-A']
#		cmd = ["cat"]
		self.cmd = cmd
		self.debugf = None

	def debug(self, str):
		if self.debugf == None:
			self.debugf = open(".debug.addr2line", 'w+')
		self.debugf.write(str)
		self.debugf.write("\n")

	def map(self, addr):
		self.p = subprocess.Popen(self.cmd,
					shell=False,
					stdin=subprocess.PIPE,
					stdout=subprocess.PIPE,
					stderr=subprocess.STDOUT, bufsize=0)
		(out, err) = self.p.communicate("0x%x\n" % addr)

		lines = string.split(out, '\n')
		sym = lines[0]
		l = lines[1].split(' ')
		loc = l[0].split(':')
#		self.debug(str(addr))
#		self.debug(lines[0])
#		self.debug(lines[1])
		return [sym, loc]
