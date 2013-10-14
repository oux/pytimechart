# 2013 September 10th   Stephane GASPARINI/Sebastien MICHEL Creation
#
# to use with Android systrace/atrace markers (traceBegin, traceEnd java call or their C/C++ equivalent)
# This plug-in is displaying systrace user tag as process line in pytime chart.
# it display it in two ways that serve different purpose.
# - a la systrace the tags are displayed as stack, representing the call level, it gives a result
#   comparable to sytrace
#   Colors are those process lines are Cyan are alike
# - as the previous mode is not always useful when you add user tag to the code you are analysing
#   the usertag are also displayed as another process line with the name of the user tag
#   the color of those tag are Purple are alike.
#
# Here is the list of tags tracked by this plug-in.
# tracing_mark_write: S|pid|usertag|value
# tracing_mark_write: F|pid|usertag|value
# tracing_mark_write: C|pid|usertag|value
# tracing_mark_write: B|pid|usertag
# tracing_mark_write: E
#
# Android systrace used atrace command that itself uses ftrace linux trace.
# You can add your own trace to help you figure ou when a particular procedure is exectuted
# or whatever you need.
# the Java API are traceBegin("your string") and traceEnd()
# those API are only acailable in the framework.
#
# In case you need to use it outside of the Framework then you need to implement them
#
# e.g. in Java
# 1) add the following import to your source
# import android.os.Debug;
# import java.io.BufferedWriter;
# import java.io.FileWriter;
# import java.io.IOException;
# import android.os.Process;
#
# 2) add the following declaration to your trace
#   static final String FILE_TRACE_MARKER = "/sys/kernel/debug/tracing/trace_marker";
#   private BufferedWriter traceMarker;
#   private int myPid;
#
# 3) then add the traceBegin and traceEnd method to your class
#	public void traceBegin(String name) {
#	    try {
#	        traceMarker.write("B|" + myPid + "|" + name);
#	        traceMarker.flush();
#	    } catch (IOException io) {
#	        Log.d(TAG, "cannot write:" + FILE_TRACE_MARKER);
#	    }
#	}
#
#	public void traceEnd() {
#	    try {
#	        traceMarker.write("E");
#	        traceMarker.flush();
#	    } catch (IOException io) {
#	        Log.d(TAG, "cannot write:" + FILE_TRACE_MARKER);
#	    }
#	}
# 4) then you need to initialize the file writer
#		    try {
#		        traceMarker = new BufferedWriter(new FileWriter(FILE_TRACE_MARKER));
#		    } catch (IOException io) {
#		        Log.d(TAG, " " + io.getMessage() + FILE_TRACE_MARKER) ;
#		    }
#		    myPid = Process.myPid();
#
#    This initialization will cause an error as Java assumes read and write access
#    to the file where trace_marker file is only writable.
#    You can ignore this error
#
# 5) you are done just call traceBegin("your string"); and traceEnd();
#    where you need, don't forget the End !
#
# You may might need to also track things in kernel.
# to do so there is a ftrace API in the kernel that will write to trace_marker file
# trace_printk("your string")
# you can use this API to activate trace in kernel.
#
# 1) add the right include
# #include <linux/ftrace.h>
#
# 2) then call trace_printk and format the string inside as the systrace API is doing
# e.g.
# trace_printk("S|0|mmc_request|mmc_request\n");
# trace_printk("F|0|mmc_request|mmc_request\n");
# or
# trace_printk("B|0|mmc_request\n");
# trace_printk("E\n");
#


from timechart.plugin import *
from timechart import colors
from timechart.model import tcProcess, _pretty_time
from enthought.traits.api import Bool
import logging
import re

debug = False
ctx = {}
ctx_start_ts = {}
ctx_start_usertag = {}

class tracing_mark_write(plugin):
    additional_colors = """
    tracing_mark_write_counter_bg     #00ffff
    tracing_mark_write_sync_bg        #00ffBB
    tracing_mark_write_async_bg       #00ff77
    tracing_mark_write_sysutag_bg     #CC99FF
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
       "tracing_mark_write_sysutag":(tcProcess, SYSUTAG_CLASS),
    }
    @staticmethod
    def do_all_events(proj,event):
        # this method is catching the trace_prink of the following form
        # <func_name>: S|pid|usertag|value
        # <func_name>: F|pid|usertag|value
        # <func_name>: C|pid|usertag|value
        # <func_name>: B|pid|usertag
        # <func_name>: E
        if event.event != "tracing_mark_write" :
            match_SFC_Events = re.match(r'([SFC])\|([0-9]*)\|(.*)\|(.*)',event.event_arg,flags=0)
            match_B_Events = re.match(r'(B)\|([0-9]*)\|(.*)',event.event_arg,flags=0)
            match_E_Events = re.match(r'(E)',event.event_arg,flags=0)
            if match_SFC_Events:
                event.traceEvent = match_SFC_Events.group(1)
                event.pid = match_SFC_Events.group(2)
                event.usertag = match_SFC_Events.group(3)
                event.value = match_SFC_Events.group(4)
                tracing_mark_write.do_event_tracing_mark_write(proj,event)
            if match_B_Events :
                event.traceEvent = match_B_Events.group(1)
                event.pid = match_B_Events.group(2)
                event.usertag = match_B_Events.group(3)
                tracing_mark_write.do_event_tracing_mark_write(proj,event)
            if match_E_Events:
                event.traceEvent = match_E_Events.group(1)
                tracing_mark_write.do_event_tracing_mark_write(proj,event)

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
            # create a process line that aims to be stacked close to process a la systrace
            process = proj.generic_find_process_with_tgid(event.common_tgid, event.common_pid, "%s|%s|%03d" % (event.common_comm, evtype, ctx[key]), "tracing_mark_write_"+sync)
            # create a process line that aims to be user trace independant of the process
            usertag = proj.generic_find_process(event.common_pid,event.usertag+"|"+ str(ctx[key]),"tracing_mark_write_sysutag")
            proj.generic_process_start(process,event,False)
            proj.generic_process_start(usertag,event,False)
            # collect timestamp on user tag for later use on 'E' marker
            ctx_start_ts[key,ctx[key]] = event.timestamp
            ctx_start_usertag[key,ctx[key]] = event.usertag
            process['comments'].append(event.usertag+"(Did not finish)")
            usertag['comments'].append(event.usertag+"(Did not finish)")
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

                process = proj.generic_find_process_with_tgid(event.common_tgid, event.common_pid, "%s|%s|%03d" % (event.common_comm, evtype, ctx[key]), "tracing_mark_write_"+sync)
                usertag = proj.generic_find_process(event.common_pid,ctx_start_usertag[key,ctx[key]]+"|"+ str(ctx[key]),"tracing_mark_write_sysutag")
            except KeyError:
                # hit a TraceEnd before a TraceBegin marker
                return
            proj.generic_process_end(process,event,False)
            proj.generic_process_end(usertag,event,False)

            # compute duration and add comment to plot
            try:
                process['comments'].pop()
                usertag['comments'].pop()
                duration=event.timestamp-ctx_start_ts[key,ctx[key]]
                process['comments'].append(ctx_start_usertag[key,ctx[key]]+"("+_pretty_time(duration)+")")
                usertag['comments'].append(ctx_start_usertag[key,ctx[key]]+"("+_pretty_time(duration)+")")
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
            process = None
            try:
                process = proj.generic_find_process(-1,event.usertag,"tracing_mark_write_counter")
                proj.generic_process_end(process,event,False)
            except:
                pass
            if event.value is not "0":
                proj.generic_process_start(process,event,False)
                process['comments'].append(event.value)

        else :
            # tracing_mark_write event malformed
            logging.warning("tracing_mark_write plug-ins: line %d malformed tracing_mark_write event.traceEvent - Ignoring", event.linenumber)
            return

plugin_register(tracing_mark_write)
