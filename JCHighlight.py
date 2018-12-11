from idautils import *
from idaapi import *
import idc
from re import *


AUTHOR  = "A1phaZer0"
VERSION = "1.0"
DATE    = "2018.12"

#
# Print banner in Output Window
#
def banner():
    banner_options = (VERSION, AUTHOR, DATE)
    banner_title   = "Call/Jmp highlight v%s - (c) %s - %s" % banner_options

    print "--[" + banner_title + "]--\n"

banner()

#
# Highlight Calls and Jmps
#
def highlight():
    # 
    for ea in Segments():
        seg = getseg(ea)
        name = get_segm_name(seg)
        # if name starts with .text
        match_text = match('^\.text.*', name)
        if match_text:
            # Get start and end of .text segment
            #seg      = get_segm_by_sel(selector_by_name(".text*"))
            segStart = get_segm_start(ea)
            segEnd   = get_segm_end(ea)

            heads = Heads(segStart, segEnd)

            # direct, indirect far, indirect near
            funcCalls = [NN_call, NN_callfi, NN_callni]
            funcJmps  = [NN_jmp, NN_jmpfi, NN_jmpni]

            for line in heads:
                decode_insn(line)
                if cmd.itype in funcCalls or cmd.itype in funcJmps:
                    m = print_insn_mnem(line)
                    # do not highlight jmp loc_xxxx
                    if m == 'jmp':
                        inst = generate_disasm_line(line, 0)
                        match_loc = match(".*loc[r|_].*", inst)
                        if match_loc:
                            continue
                    #                       0xBBGGRR
                    set_color(line, CIC_ITEM, 0x222222)



#
# Steps of creating a plugin
# 
# 1. Create handler which contains 2 member functions: activate, update
# 2. Create action descriptor describing plugin information including handler
# 3. Register action by action descriptor
#


class JmpCallHighlight(action_handler_t):
    def __init__(self):
        action_handler_t.__init__(self)

    # Run when invoked
    def activate(self, ctx):
        # call a function
        highlight()
        # or invoke a script
        #g = globals()
        #home = idadir("plugins")
        #IDAPython_ExeScript(home + "\\some.py", g)

    # Always stays there
    def update(self, ctx):
        return AST_ENABLE_ALWAYS

class HighlightPlugin(plugin_t):
    flags         = PLUGIN_FIX
    comment       = ""
    help          = "Jmp/Call Highlighter"
    wanted_name   = "JCH"
    wanted_hotkey = ""


    # register action
    def action_reg(self):
        action_desc = action_desc_t(
                'my:highlightaction',      # unique action name
                'J/C Highlight',           # action text
                JmpCallHighlight(),        # action handler
                'Ctrl+H',                  # Optional, hotkey
                ''                         # Optional, tooltip
        )

        register_action(action_desc)

        attach_action_to_menu(
            'Edit',                        # path of where to add action
            'my:highlightaction',          # action name
            SETMENU_APP)

        form = get_current_tform()
        attach_action_to_popup(form, None, "my:highlightaction", None)

    def init(self):
        """
        Called by IDA
        """
        try:
            self._install_plugin()

        except Exception as e:
            form = get_current_tform()
            pass

        return PLUGIN_KEEP

    def _install_plugin(self):
        """
        Inintialize and install plugin into IDA
        """
        self.action_reg()
        self._init()

    def term(self):
        pass

    def run(self, arg = 0):
        obj = JmpCallHighlight()
        obj.activate(self)

def PLUGIN_ENTRY():
    return HighlightPlugin()

# Find all heads, use 0, 0xffffffff if you want use this script when IDA starts
dgrsFuncs = ["snprintf", "sprintf", "memcpy",   "memmove", \
             "strcat",   "strcpy",  "vsprintf", "gets",    \
             "strncpy",  "strncat", "snprintf", "fgets",   \
             "strlen",   "scanf",   "fscanf",   "sscanf",  \
             "vscanf",   "vsscanf", "vfscanf",  "realpath",\
             "getopt",   "getpass", "strecat",  "strecpy", \
             "strtrns",  "getwd",   "read"]

