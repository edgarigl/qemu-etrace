#!/usr/bin/env python
#
#

import sys
import os
import getopt
import time
import etrace

import curses

from elftools.common.py3compat import maxint, bytes2str
from elftools.elf.elffile import ELFFile

def usage():
	print "--help          Show help"
	print "--trace         filename of trace"

class traceview(object):

	def __init__(self, screen, e, elf_name, comp_dir):
		self.fcache = {}
		self.e = e
		self.comp_dir = comp_dir
		self.screen = screen
		self.dw = None
		self.dw_loc = None
		self.record = None
		self.record_idx = 0
		self.record_pos = 0
		self.symname = ""
		self.file = ""
		self.line = -1
		self.search_sym = ""
		self.debugf = None
		if elf_name != None:
			self.screen.clear()
			self.screen.addstr(0, 0, "Processing ELF file.")
			self.screen.refresh()
			self.ef = open(elf_name, 'rb')
			self.elffile = ELFFile(self.ef)
			self.dw = self.elffile.get_dwarf_info()
			self.dw_loc = self.generate_file_line()
			self.screen.clear()

	def debug(self, str):
		if self.debugf == None:
			self.debugf = open(".debug", 'w+')
		self.debugf.write(str)
		self.debugf.write("\n")

	def update_file_cache(self, fname):
		try:
			f = open(fname, 'r')
		except:
			return False

		self.fcache[fname] = { "f" : f }
		self.fcache[fname] = { "lines" : f.readlines() }
		return True

	def generate_file_line(self):
		arr = {}
		prev_pos = None

		# Go over all the line programs in the DWARF information,
		# looking for one that describes the given address.
		for CU in self.dw.iter_CUs():
			lp = self.dw.line_program_for_CU(CU)
			prevstate = None
			top_DIE = CU.get_top_DIE()

			if self.comp_dir == None:
				self.comp_dir = top_DIE.attributes['DW_AT_comp_dir'].value

			for et in lp.get_entries():
				if et.state is None or et.state.end_sequence:
					continue

				if prev_pos:
					for i in range(prev_pos,
						et.state.address - 1, 4):
						arr[i] = arr[prev_pos]

				filename = lp['file_entry'][et.state.file - 1].name

				dir_i = lp['file_entry'][et.state.file - 1].dir_index
				if dir_i > 0:
					dir = lp['include_directory'][dir_i - 1]
				else:
					dir = b'.'
				filename = '%s/%s/%s' % (self.comp_dir,
							bytes2str(dir), filename)
				self.update_file_cache(filename)
				arr[et.state.address] = [filename, et.state.line - 1, ""]
				print("%x:%s\r" % (et.state.address, filename))
				prev_pos = et.state.address
				prevstate = et.state

			for DIE in CU.iter_DIEs():
				name = ""
				if DIE.tag == 'DW_TAG_subprogram':
					try:
						lowpc = DIE.attributes['DW_AT_low_pc'].value
						highpc = DIE.attributes['DW_AT_high_pc'].value
					except:
						continue
					for adr in range(lowpc & ~3, highpc, 4):
						try:
							name = DIE.attributes['DW_AT_name'].value
						except KeyError:
							continue
						try:
							arr[adr][2] = name
						except:
							continue
		return arr

	def show_file_contents(self, lines, line_nr):
		(h, w) = self.screen.getmaxyx()
		h -= 4
		start = line_nr - h / 2
		if start < 0:
			start = 0
		for i in range(4, h - 1):
			try:
				str = "%4.4d:%s" % (start + i, lines[start + i])
			except:
				break
			if (start + i) == line_nr:
				self.screen.addstr(i, 0, str, curses.A_REVERSE)
			else:
				self.screen.addstr(i, 0, str)

	def step_end_of_subrecord(self, r):
		self.record_pos = r.all.ex.ex32[self.record_idx].end - 4
		if self.record_pos < r.all.ex.ex32[self.record_idx].start:
			self.record_pos = r.all.ex.ex32[self.record_idx].start

	def step_end_of_record(self, r):
		self.record_idx = r.all.ex.nr - 1
		self.step_end_of_subrecord(r)

	def step_start_of_record(self, r):
		self.record_idx = 0
		if r and r.hdr.type == self.e.TYPE_EXEC:
			self.record_pos = r.all.ex.ex32[self.record_idx].start

	def step_existing_record_back(self, r):
		if r == None or r.hdr.type != self.e.TYPE_EXEC:
			r = self.e.stepb()
			if r and r.hdr.type == self.e.TYPE_EXEC:
				self.step_end_of_record(r)
			return r

		# Now we know we've got an exec record.
		# Step back.
		if self.record_pos <= r.all.ex.ex32[self.record_idx].start:
			if self.record_idx == 0:
				r = self.step_existing_record_back(None)
				return r
			self.record_idx -= 1
			self.step_end_of_subrecord(r)
			return r
		self.record_pos -= 4
		return r

	def step_record(self, count):
		if self.record and count < 0:
			r = self.step_existing_record_back(self.record)
		elif self.record and count > 0:
			r = self.record

			if r.hdr.type == self.e.TYPE_EXEC:
				self.record_pos += 4

				if self.record_pos >= r.all.ex.ex32[self.record_idx].end:
					self.record_idx += 1
					self.record_pos = r.all.ex.ex32[self.record_idx].start

				if self.record_idx == r.all.ex.nr:
					self.record = None
					r = self.e.stepf()
					self.step_start_of_record(r)
			else:
				r = self.e.stepf()
				self.step_start_of_record(r)
		else:
			if count > 0:
				r = self.e.stepf()
				self.step_start_of_record(r)
			else:
				r = self.step_existing_record_back(None)
		return r

	def step_trace_record(self, count):
		goon = True
		r = self.step_record(count)
		self.record = r
		if r == None:
			return r

		if r.hdr.type == self.e.TYPE_EXEC:
			goon = True

			self.file = ""
			self.line = -1
			if self.dw_loc:
				lines = None
				try:
					[self.file, self.line, self.symname] = self.dw_loc[self.record_pos]
					lines = self.fcache[self.file]["lines"]
				except:
					pass
				if lines:
					self.prev_file = self.file
					self.prev_line = self.line

		return r

	def step_new_exec(self, count = 1):
		r = None
		goon = True
		while goon:
			pfile = self.file
			pline = self.line
			r = self.step_trace_record(count)
			if not r:
				return None

			if r.hdr.type == self.e.TYPE_EXEC:
				goon = False
		return r

	def step_new_line(self, count = 1):
		r = None
		goon = True
		while goon:
			pfile = self.file
			pline = self.line
			r = self.step_trace_record(count)
			if not r:
				return None

			if pfile != self.file:
				goon = False

			if pline != self.line:
				goon = False

		return r

	def step_new_sym(self, newsymname = None, count = 1):
		r = None
		while True:
			if newsymname and newsymname == self.symname:
				break
			pname = self.symname
			r = self.step_new_line(count)
			if not r:
				return None

			if not newsymname and pname != self.symname:
				break
		return r


	def search_for_sym(self):
		(h, w) = self.screen.getmaxyx()
		curses.echo()
		self.screen.addstr(h - 1,0, "/")
		str = self.screen.getstr(h - 1, 1)
		str = str.rstrip()
		curses.noecho()
		return str

	def loop(self):
		c = curses.KEY_DOWN
		r = self.step_new_exec(count = 1)
		while True:
			if c == curses.KEY_DOWN:
				r = self.step_new_line()
			elif c == curses.KEY_RIGHT:
				r = self.step_new_sym(count = 1)
			elif c == curses.KEY_LEFT:
				r = self.step_new_sym(count = -1)
			if c == curses.KEY_UP:
				r = self.step_new_line(-1)
			elif c == ord('n'):
				if self.symname == self.search_sym:
					r = self.step_new_sym()
				r = self.step_new_sym(self.search_sym)
			elif c == ord('/'):
				self.search_sym = self.search_for_sym()
				r = self.step_new_sym(self.search_sym)
			elif c == ord('g'):
				self.e.reset()
				r = self.step_new_exec(count = 1)
			elif c == ord('G'):
				r = True
				while r:
					r = self.step_trace_record(count = 1)
				r = self.step_new_exec(count = -1)
			elif c == ord('q'):
				return

			if r:
				self.screen.clear()
				self.screen.addstr(0, 0,
					"%d: type=%s %x len=%d PC=%x (%x-%x)" \
					% (self.e.r_idx, self.e.type_to_name(r.hdr.type),
						r.hdr.type, r.hdr.len, self.record_pos,
						r.all.ex.ex32[self.record_idx].start,
						r.all.ex.ex32[self.record_idx].end),
						curses.A_REVERSE)

				self.screen.addstr(1, 0,
					"file=%s:%s %s" \
					% (self.file, self.line, self.symname),
					curses.A_REVERSE)

				self.screen.addstr(3, 0,
					"search=%s" \
					% (self.search_sym),
					curses.A_REVERSE)

				try:
					lines = self.fcache[self.file]["lines"]
					self.show_file_contents(lines, self.line)
				except:
					pass
				self.screen.refresh()

			r = None
			c = self.screen.getch()

def main(screen):
	args_comp_dir = None
	args_trace = None
	args_elf = None

	try:
		opts, args = getopt.getopt(sys.argv[1:],
					"h",
					["help",
					 "comp-dir=",
					 "trace=",
					 "elf=",
					]
					)
	except getopt.GetoptError, err:
		print str(err)
		usage()
		sys.exit(1)

	for o, a in opts:
		if o == "--trace":
			args_trace = a
		elif o == "--comp-dir":
			args_comp_dir = a
		elif o == "--elf":
			args_elf = a
		elif o in ("-h", "--help"):
			usage()
			sys.exit(0)
		else:
			assert False, "Unhandled option " + o

	if args_trace == None:
		print "Missing trace file"
		sys.exit(1)


	screen.clear()
	f = open(args_trace, 'rb')
	e = etrace.etrace(f)

	tv = traceview(screen, e, args_elf, args_comp_dir)

	tv.loop()

try:
	curses.wrapper(main)
except KeyboardInterrupt:
	sys.exit(0)

