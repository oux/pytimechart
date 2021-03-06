from timechart.plugin import *
from timechart import colors
from timechart.model import tcProcess

class sched(plugin):
    additional_colors = """
    sched_wakeup_arrow      #000000A0
"""
    additional_ftrace_parsers = [
        ]

    additional_process_types = {
            "kernel_process":(tcProcess, KERNEL_CLASS),
            "user_process":(tcProcess, USER_CLASS)
        }

    @staticmethod
    def do_event_sched_switch(self,event):
        # @todo differenciate between kernel and user process
        prev = self.generic_find_process_with_tgid(event.common_tgid,event.prev_pid,event.prev_comm,"user_process",event.timestamp-100000000)
        next = self.generic_find_process(event.next_pid,event.next_comm,"user_process",event.timestamp-100000000)

        self.generic_process_end(prev,event)

        if event.__dict__.has_key('prev_state') and event.prev_state == 'R':# mark prev to be waiting for cpu
            prev['start_ts'].append(event.timestamp)
            prev['types'].append(colors.get_color_id("waiting_for_cpu"))
            prev['cpus'].append(event.common_cpu)

        self.generic_process_start(next,event)

    @staticmethod
    def do_event_sched_wakeup(self,event):
        p_stack = self.cur_process[event.common_cpu]
        callee = {
                'comm' : event.comm,
                'pid'  : event.pid,
                }
        if p_stack:
            p = p_stack[-1]
            self.generic_add_wake(p, callee, event.timestamp, "sched_wakeup_arrow")
        else:
            current_task = {
                    'comm' : event.common_comm,
                    'pid'  : event.common_pid,
                    }
            self.generic_add_wake(current_task, callee, event.timestamp, "sched_wakeup_arrow")


plugin_register(sched)
