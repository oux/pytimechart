from timechart.plugin import *
from timechart import colors
from timechart.model import tcProcess

class wake_lock(plugin):
    additional_colors = """
wakelock_bg        	#D6F09D
wakelock_arrow     	#0000A0A0
"""
    additional_ftrace_parsers = [
        ('wakelock_lock',   'name=%s type=%d', 'name', 'type'),
        ('wakelock_unlock',   'name=%s', 'name'),
        ]
    additional_process_types = {
        "wakelock":(tcProcess, POWER_CLASS),
        }
    @staticmethod
    def do_event_wakelock_lock(proj,event):
        process = proj.generic_find_process(0,"wakelock:%s"%(event.name),"wakelock")
        proj.generic_process_start(process,event,False)
        current_task = {
            'comm' : event.common_comm,
            'pid'  : event.common_pid,
            }
        proj.generic_add_wake(current_task, process, event.timestamp, "wakelock_arrow")

    @staticmethod
    def do_event_wakelock_unlock(proj,event):
        process = proj.generic_find_process(0,"wakelock:%s"%(event.name),"wakelock")
        proj.generic_process_end(process,event,False)
        current_task = {
            'comm' : event.common_comm,
            'pid'  : event.common_pid,
            }
        proj.generic_add_wake(current_task, process, event.timestamp, "wakelock_arrow")

plugin_register(wake_lock)

