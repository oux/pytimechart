from timechart.plugin import *
from timechart.model import tcProcess

class graph(plugin):
    additional_colors = """
    graph_bg     #0f0fff
    """
    additional_ftrace_parsers = [
    ('graph_ent',"func=%s",'func'),
    ('graph_ret',"func=%s",'func'),
    ]
    additional_process_types = {
       "graph":(tcProcess, USER_CLASS),
    }

    @staticmethod
    def do_event_graph_ent(proj,event):
        process = proj.generic_find_process_with_tgid(event.common_tgid, event.common_pid, "func="+event.func, "graph")
        proj.generic_process_start(process,event,False)

    @staticmethod
    def do_event_graph_ret(proj,event):
        process = proj.generic_find_process_with_tgid(event.common_tgid, event.common_pid, "func="+event.func, "graph")
        proj.generic_process_end(process,event,False)

plugin_register(graph)
