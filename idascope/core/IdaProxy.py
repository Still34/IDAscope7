#!/usr/bin/python
########################################################################
# Copyright (c) 2012
# Daniel Plohmann <daniel.plohmann<at>gmail<dot>com>
# Alexander Hanel <alexander.hanel<at>gmail<dot>com>
# All rights reserved.
########################################################################
#
#  This file is part of IDAscope
#
#  IDAscope is free software: you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see
#  <http://www.gnu.org/licenses/>.
#
########################################################################

import idaapi
import idautils
import idc
import ida_segment
import ida_bytes
import ida_frame
import ida_kernwin
import ida_name
import ida_funcs
import ida_bytes
import ida_nalt
import ida_ida

class IdaProxy():
    """
    This class serves as a generic proxy to the IDA Pro Python API. This is necessary because while running the
    plugin, dynamic references to the loaded Python modules get lost when inside functions called by Qt.
    As a side effect, we can also do central error handling in this proxy class.
    """

    def __init__(self):
        self.idc = idc
        self.idaapi = idaapi
        self.idautils = idautils
        self.ida_segment = ida_segment
        self.ida_frame = ida_frame
        self.ida_bytes = ida_bytes
        self.ida_kernwin = ida_kernwin
        self.ida_bytes = ida_bytes
        self.ida_funcs = ida_funcs
        self.ida_nalt = ida_nalt
        self.ida_ida = ida_ida
        # debug output
        self.verbose = False
        # constants
        self.BAD_ADDR = self.idaapi.BADADDR
        self.CIC_ITEM = self.idc.CIC_ITEM
        self.FF_LABL = self.idc.FF_LABL
        self.FL_CN = self.idc.fl_CN
        self.FL_CN = self.idc.fl_CN
        self.FUNC_LIB = self.idaapi.FUNC_LIB
        self.FUNCATTR_END = self.idc.FUNCATTR_END
        self.INF_SHORT_DEMNAMES = self.idc.INF_SHORT_DEMNAMES
        self.SN_NOWARN = self.idc.SN_NOWARN
        self.SN_NOCHECK = self.idc.SN_NOCHECK
        self.SA_REL_BYTE = self.idc.saRelByte
        self.SA_REL_PARA = self.idc.saRelPara
        self.SC_PRIV = self.idc.scPriv
        self.SC_PUB = self.idc.scPub
        self.SEGMOD_KILL = self.idaapi.SEGMOD_KILL
        self.SEARCH_DOWN = 1
        self.MFF_FAST = self.idaapi.MFF_FAST
        self.STRTYPE_C = self.ida_nalt.STRTYPE_C
        self.FUNCATTR_START = self.idc.FUNCATTR_START

###############################################################################
# From idc.py
###############################################################################

    def AddHotkey(self, hotkey, function):
        return self.idc.add_idc_hotkey(hotkey, function)

    def AddSeg(self, start_ea, end_ea, base, use32, align, comb):
        return self.idc.AddSeg(start_ea, end_ea, base, use32, align, comb)

    def Byte(self, byte):
        return self.idc.get_wide_byte(byte)

    def Comment(self, addr):
        return self.idc.get_cmt(addr, 0)

    def DelSeg(self, address, flags):
        return self.ida_segment.del_segm(address, flags)

    def Demangle(self, name, disable_mask):
        return self.idc.demangle_name(name, disable_mask)

    def Dword(self, addr):
        return self.idc.get_wide_dword(addr)

    def FirstSeg(self):
        return self.idc.get_first_seg()

    def get_byte(self, address):
        return self.idaapi.get_byte(address)

    def GetCommentEx(self, ea, repeatable):
        return self.idaapi.GetCommentEx(ea, repeatable)

    def GetDisasm(self, address):
        return self.idc.GetDisasm(address)

    def GetFlags(self, address):
        return self.ida_bytes.get_full_flags(address)

    def GetFunctionAttr(self, ea, attr):
        return self.idc.get_func_attr(ea, attr)

    def GetFunctionCmt(self, ea, repeatable):
        return self.idc.get_func_cmt(ea, repeatable)

    def GetFunctionFlags(self, address):
        return self.idc.get_func_flags(address)

    def GetFunctionName(self, address):
        return self.idc.get_func_name(address)

    def GetFrame(self, ea):
        return self.ida_frame.get_frame(ea)

    def GetLongPrm(self, offset):
        return self.idc.get_inf_attr(offset)

    def GetLastMember(self, sid):
        return self.idc.get_last_member(sid)

    def GetMnem(self, address):
        return self.idc.print_insn_mnem(address)

    def GetMemberComment(self, sid, member_offset, repeatable):
        return self.idc.get_member_cmt(sid, member_offset, repeatable)

    def GetMemberFlag(self, sid, member_offset):
        return self.idc.get_member_flag(sid, member_offset)

    def GetMemberName(self, sid, member_offset):
        return self.idc.get_member_name(sid, member_offset)

    def GetMemberSize(self, sid, member_offset):
        return self.idc.get_member_size(sid, member_offset)

    def GetMemberOffset(self, sid, member_name):
        return self.idc.get_member_offset(sid, member_name)

    def GetOpType(self, address, index):
        return self.idc.get_operand_type(address, index)

    def GetOperandValue(self, address, index):
        return self.idc.get_operand_value(address, index)

    def GetString(self, address):
        return self.idc.get_strlit_contents(address)

    def GetType(self, address):
        type_at_address = self.idc.get_type(address)
        if type_at_address is not None:
            return type_at_address
        else:
            if self.verbose:
                print ("[!] IdaProxy.FlowChart: No type information for 0x%x available, returning \"\".") % address
            return ""

    def is_code(self, flags):
        return self.ida_bytes.is_code(flags)

    def Jump(self, address):
        return self.ida_kernwin.jumpto(address)

    def LocByName(self, name):
        return self.idc.get_name_ea_simple(name)

    def MakeFunction(self, instruction):
        return self.ida_funcs.add_func(instruction)

    def MakeNameEx(self, address, name, warning_level):
        return self.idc.set_name(address, name, warning_level)

    def MakeRptCmt(self, ea, comment):
        return self.idc.set_cmt(ea, comment, 1)

    def Name(self, address):
        return self.idc.get_name(address, ida_name.GN_VISIBLE)

    def NextSeg(self, address):
        return self.idc.get_next_seg(address)

    def PatchByte(self, address, byte):
        self.ida_bytes.patch_byte(address, byte)

    def PrevHead(self, ea, minea=0):
        return self.idc.prev_head(ea, minea)

    def NextHead(self, ea, minea=0):
        return self.idc.next_head(ea, minea)

    def RptCmt(self, ea):
        return self.idc.get_cmt(ea, 1)

    def SegEnd(self, address):
        return self.idc.get_segm_end(address)

    def SegName(self, address):
        return self.idc.get_segm_name(address)

    def SegRename(self, address, name):
        return self.idc.set_segm_name(address, name)

    def SegStart(self, address):
        return self.idc.get_segm_start(address)

    def SetColor(self, address, location_type, color):
        return self.idc.set_color(address, location_type, color)

    def GetOpnd(self, ea, n):
        return self.idc.print_operand(ea, n)

###############################################################################
# From idaapi.py
###############################################################################

    def compile_idc_text(self, line):
        return self.idaapi.compile_idc_text(line)

    def find_not_func(self, *args):
        return self.idaapi.find_not_func(*args)

    def find_binary(self, *args):
        return self.idaapi.find_binary(*args)

    def FlowChart(self, function_address):
        function_chart = []
        try:
            function_chart = self.idaapi.FlowChart(function_address)
        except:
            if self.verbose:
                if function_address is not None:
                    print ("[!] Trying to resolve an API address in non-function code at location: 0x%x, continuing " \
                        + "analysis...") % function_address
                else:
                    print ("[!] IdaProxy.FlowChart: Tried to create a FlowChart on None object, skipping function.")
        return function_chart

    def get_func(self, function_address):
        return self.idaapi.get_func(function_address)

    def get_highlighted_identifier(self):
        return self.idaapi.get_highlighted_identifier()

    def is_strlit(self, flags):
        return self.ida_bytes.is_strlit(flags)

    def minEA(self):
        return self.ida_ida.idainfo.omin_ea

    def refresh_idaview_anyway(self):
        return self.idaapi.refresh_idaview_anyway()

    def get_import_module_qty(self):
        return self.idaapi.get_import_module_qty()

    def get_import_module_name(self, mod_index):
        return self.idaapi.get_import_module_name(mod_index)

    def enum_import_names(self, mod_index, py_cb):
        return self.idaapi.enum_import_names(mod_index, py_cb)

###############################################################################
# From idautils.py
###############################################################################

    def CodeRefsFrom(self, source, flow):
        return self.idautils.CodeRefsFrom(source, flow)

    def CodeRefsTo(self, destination, flow):
        return self.idautils.CodeRefsTo(destination, flow)

    def DataRefsFrom(self, source):
        return self.idautils.DataRefsFrom(source)

    def DataRefsTo(self, destination):
        return self.idautils.DataRefsTo(destination)

    def execute_sync(self, *args):
        return self.idaapi.execute_sync(*args)

    def FuncItems(self, function_address):
        return self.idautils.FuncItems(function_address)

    def Functions(self, start_address=None, end_address=None):
        return self.idautils.Functions(start_address, end_address)

    def Heads(self, start_address=None, end_address=None):
        return self.idautils.Heads(start_address, end_address)

    def Names(self):
        return self.idautils.Names()

    def Segments(self):
        return self.idautils.Segments()

    def XrefsTo(self, ea, flag=0):
        return self.idautils.XrefsTo(ea, flag)
