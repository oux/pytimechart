# 2013 September 10th   Stephane GASPARINI/Sebastien MICHEL Creation
#
# to use with Android systrace/atrace markers (traceBegin, traceEnd java call or their C/C++ equivalent)
# tracing_mark_write: S|pid|usertag|value
# tracing_mark_write: F|pid|usertag|value
# tracing_mark_write: C|pid|usertag|value
# tracing_mark_write: B|pid|usertag
# tracing_mark_write: E

from timechart.plugin import *
from timechart import colors
from timechart.model import tcProcess, _pretty_time
import logging

debug = False
ctx = {}
ctx_start_ts = {}
ctx_start_usertag = {}

class tracing_mark_write(plugin):
    additional_colors = """
    tracing_mark_write_counter_bg		  #00ffff
    tracing_mark_write_sync_bg		      #00ffBB
    tracing_mark_write_async_bg		      #00ff77
    """
    additional_ftrace_parsers = [
    ('tracing_mark_write',"%s",'traceEvent'),
    ('tracing_mark_write',r"%s\|%d\|%s",'traceEvent','pid','usertag'),
    ('tracing_mark_write',r"%s\|%d\|%s\|%s",'traceEvent','pid','usertag','value'),
    ]
    additional_process_types = {
       "tracing_mark_write_counter":(tcProcess, MISC_TRACES_CLASS),
       "tracing_mark_write_sync":(tcProcess, USER_CLASS),
       "tracing_mark_write_async":(tcProcess, USER_CLASS),
    }

    @staticmethod
    def do_event_tracing_mark_write(proj,event):
        # doing sanity checking: when funtion tracer is activated
        # could get corrupted tracing_mark_write event
        if len(event.traceEvent) != 1 :
            logging.warning("tracing_mark_write plug-ins: line %d malformed tracing_mark_write event - Ignoring", event.linenumber)
            logging.warning("likely you had trace buffer underrun")
            return

        if event.traceEvent == "B" or event.traceEvent == "E":
            sync = "sync"
            evtype = "sync"
        elif event.traceEvent == "S" or event.traceEvent == "F":
            sync = "async"
            evtype = "async"
        elif event.traceEvent == "C":
            sync = "counter"
            evtype = "counter"

        if sync == "async":
            key=(event.common_comm,event.common_pid,event.value)
            evtype=event.value
        elif sync == "sync":
            key=(event.common_comm,event.common_pid,evtype)


        # #######################
        # TraceBegin marker code
        # #######################
        if event.traceEvent == "B" or event.traceEvent == "S":

            if not hasattr(event,'usertag') or not hasattr(event,'pid'):
                logging.warning("tracing_mark_write plug-ins: line, %d malformed tracing_mark_write missing attribute- Ignoring", event.linenumber)
                logging.warning("likely you had trace buffer underrun")
                return
            # 'tracing_mark_write: B|pid|usertag' found
            try:
                ctx[key] += 1
            except KeyError:
                ctx[key] = 0
            process = proj.generic_find_process(event.common_pid,event.common_comm+"|"+evtype+"|"+("%03d" % ctx[key]),"tracing_mark_write_"+sync)
            proj.generic_process_start(process,event,False)
            # collect timestamp on user tag for late use on 'E' marker
            ctx_start_ts[key,ctx[key]] = event.timestamp
            ctx_start_usertag[key,ctx[key]] = event.usertag
            process['comments'].append(event.usertag+"(Did not finish)")
            if debug:
                logging.debug("------------------------------------->\n")
                if sync == "async":
                    logging.debug("key: (('%s', %s, %s), %s)", event.common_comm, event.common_pid, event.value, ctx[key])
                else:
                    logging.debug("key: (('%s', %s, %s), %s)", event.common_comm, event.common_pid, evtype, ctx[key])
                logging.debug("ctx %s" %(ctx))
                logging.debug("ctx_start_ts %s", (ctx_start_ts))
                logging.debug("ctx_start_usertag %s\n", (ctx_start_usertag))
                logging.debug("--\n")

        # #######################
        # TraceEnd marker code
        # #######################
        elif event.traceEvent == "E" or event.traceEvent == "F":
            try:
                if debug:
                    logging.debug("--\n")
                    if sync == "async":
                        logging.debug("key: (('%s', %s, %s), %s)", event.common_comm, event.common_pid, event.value, ctx[key])
                    else:
                        logging.debug("key: (('%s', %s, %s), %s)", event.common_comm, event.common_pid, evtype, ctx[key])
                    logging.debug("ctx_start_ts %s", ctx_start_ts)
                    logging.debug("ctx_start_usertag %s", ctx_start_usertag)
                    logging.debug("ctx %s\n<-------------------------------------\n", ctx)

                process = proj.generic_find_process(event.common_pid,event.common_comm+"|"+evtype+"|"+("%03d" % ctx[key]),"tracing_mark_write_"+sync)
            except KeyError:
                # hit a TraceEnd before a TraceBegin marker
                return
            proj.generic_process_end(process,event,False)

            # compute duration and add comment to plot
            try:
                process['comments'].pop()
                duration=event.timestamp-ctx_start_ts[key,ctx[key]]
                process['comments'].append(ctx_start_usertag[key,ctx[key]]+"("+_pretty_time(duration)+")")
            except IndexError:
                # missing corresponding B marker in trace
                logging.debug( "IndexError \n%s\n", event)
            except KeyError:
                logging.debug("KeyError \n%s\n", event)
            ctx[key] -= 1

        # #######################
        # TraceCounter marker code
        # #######################
        elif event.traceEvent == "C":
            process = proj.generic_find_process(-1,event.usertag,"tracing_mark_write_counter")
            proj.generic_process_start(process,event,False)
            process['comments'].append(str(event.value))

        else :
            # tracing_mark_write event malformed
            logging.warning("tracing_mark_write plug-ins: line %d malformed tracing_mark_write event.traceEvent - Ignoring", event.linenumber)
            return

plugin_register(tracing_mark_write)
