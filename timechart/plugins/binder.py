# 2013 September 12th   Sebastien MICHEL Creation
#
# To see Android binder transactions on ftrace:
# for event in binder/binder_transaction binder/binder_transaction_received
# do
#    adb shell "echo 1 > /d/tracing/events/$event/enable"
# done

from timechart.plugin import *
from timechart import colors
from timechart.model import tcProcess
import logging

debug = False
ctx = {}

class binder(plugin):

    additional_colors = """
    binder_arrow		  #ff0000A0
    """

    additional_ftrace_parsers = [
    ('binder_transaction','transaction=%d dest_node=%d dest_proc=%d dest_thread=%d reply=%d flags=%s code=%s','transaction_id','dest_node','dest_proc','dest_thread','reply','flags','code'),
    ('binder_transaction_received','transaction=%d','transaction_id'),
    ]

    @staticmethod
    def do_event_binder_transaction(proj,event):
        if debug: logging.debug("binder_send: %d", event.transaction_id)
        ctx[event.transaction_id] = {
                'comm' : proj.generic_get_current_comm(event.common_pid),
                'pid'  : event.common_pid,
                }

    @staticmethod
    def do_event_binder_transaction_received(proj,event):
        if debug: logging.debug("binder_recv: %d", event.transaction_id)
        try:
            caller = ctx[event.transaction_id]
            callee = {
                    'comm' : proj.generic_get_current_comm(event.common_pid),
                    'pid'  : event.common_pid,
                    }
            proj.generic_add_wake(caller, callee, event.timestamp, "binder_arrow")
        except KeyError:
            logging.warning("binder parsing error (not sender found for %s(last comm:%s)-%d transaction=%d)", event.common_comm, proj.generic_get_current_comm(event.common_pid), event.common_pid, event.transaction_id)
            return

plugin_register(binder)
