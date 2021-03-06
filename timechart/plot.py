from enthought.chaco.api import ArrayDataSource, DataRange1D, LinearMapper,BarPlot, LinePlot, \
                                 ScatterPlot, PlotAxis, PlotGrid,OverlayPlotContainer, VPlotContainer,add_default_axes, \
                                 add_default_grids,VPlotContainer
from enthought.chaco.tools.api import PanTool, ZoomTool,RangeSelection,RangeSelectionOverlay
from enthought.chaco.api import create_line_plot
from enthought.traits.ui.api import View,Item,VGroup,HGroup, CodeEditor
from enthought.traits.api import HasTraits,DelegatesTo,Trait
from enthought.traits.api import Float, Instance, Int,Bool,Str,Unicode,Enum,Button
from enthought.chaco.api import AbstractOverlay, BaseXYPlot
from enthought.chaco.label import Label
from enthought.kiva.traits.kiva_font_trait import KivaFont
from enthought.enable.api import black_color_trait, KeySpec

from model import tcProject, tcProcess, _pretty_time
from colors import get_aggcolor_by_id,get_color_id
import tools
from numpy import linspace,arange,amin,amax
from math import log
from numpy import array, ndarray,argmax,searchsorted,mean
from numpy import array, compress, column_stack, invert, isnan, transpose, zeros,ones
from enthought.traits.api import List
from enthought.enable.colors import ColorTrait
from enthought.pyface.timer import timer

process_colors=[0x000000,0x555555,0xffff88,0x55ffff,0xAD2D2D, 0xeeeeee,0xeeaaaa,0xaaaaee,0xee0000]
class TimeChartOptions(HasTraits):
    remove_pids_not_on_screen = Bool(True)
    show_ipc_events = Bool(False)
    show_p_states = Bool(True)
    show_c_states = Bool(True)
    auto_zoom_y = Bool(True)
    use_overview = Bool(True)
    sysusertag = Bool(True)
    show_sysusertag = Bool(False)
    show_marks = Bool(True)

    proj = tcProject

    def connect(self,plot):
        self.auto_zoom_timer = timer.Timer(300,self._auto_zoom_y_delayed)
        self.auto_zoom_timer.Stop()
        self.plot = plot
    def _minimum_time_filter_changed(self):
        self.plot.invalidate()
    def _remove_pids_not_on_screen_changed(self):
        self.plot.invalidate()
    def _show_ipc_events_changed(self):
        self.plot.invalidate()
    def _show_p_states_changed(self):
        self.plot.invalidate()
    def _show_c_states_changed(self):
        self.plot.invalidate()
    def _use_overview_changed(self):
        self.plot.invalidate()
    def _show_sysusertag_changed(self):
        self.plot.invalidate()
    def _show_marks_changed(self):
        self.plot.invalidate()
    def _auto_zoom_y_changed(self,val):
        self.plot.auto_zoom_y()
        self.auto_zoom_timer.Stop()
    def _auto_zoom_y_delayed(self):
        self.plot.auto_zoom_y()
        self.auto_zoom_timer.Stop()
    def _on_toggle_autohide(self, value):
        self.remove_pids_not_on_screen = value
    def _on_toggle_ipc(self, value):
        self.show_ipc_events = value
    def _on_toggle_cpuidle(self, value):
        self.show_c_states = value
    def _on_toggle_cpufreq(self, value):
        self.show_p_states = value
    def _on_toggle_auto_zoom_y(self, value):
        self.auto_zoom_y = value
    def _on_toggle_overview(self, value):
        self.use_overview = value
    def _on_toggle_sysutag(self, value):
        self.show_sysusertag = value
    def _on_toggle_marks(self, value):
        self.show_marks = value

class TextView(HasTraits):
    text = Str
    save = Button()
    def __init__(self,text,title):
        self.text = text
        self.trait_view().title = title

    traits_view = View(
        Item('text',style="readonly",show_label=False, editor=CodeEditor()),
        HGroup(
            Item('save'),
            show_labels = False),
        resizable = True,
        width = 1024,
        height = 600,
        )
    def _save_changed(self):
        from window import save_dialog
        fn = save_dialog()
        if fn:
            try:
                f = open(fn,"w")
                f.write(self.text)
                f.close()
            except:
                print "unable to write file..."
class RangeSelectionTools(HasTraits):
    start = 0
    end = 0
    def connect(self,plot):
        self.plot = plot
        plot.range_selection.on_trait_change(self._selection_update_handler, "selection")
        self._timer = timer.Timer(100,self._selection_updated_delayed)
        self._timer.Stop()
    def _selection_update_handler(self,value):
        if value is not None :
            self.start, self.end = amin(value), amax(value)
            time = self.end-self.start
            self.plot.selection_status = "selection time:%d.%03d %03ds  left=%d.%03d %03ds  right=%d.%03d %03ds"%(time/1000000,(time/1000)%1000,time%1000, self.start/1000000, (self.start/1000)%1000, self.start%1000, self.end/1000000, (self.end/1000)%1000, self.end%1000)
            self.plot.immediate_invalidate()
            self._timer.Stop()
            self._timer.Start()
        else:
            self.plot.selection_status = ""
            self.start = 0
            self.end = 0
    def _on_zoom(self):
        if self.end != self.start:
            self.plot.index_range.high = self.end
            self.plot.index_range.low = self.start
            self.plot.range_selection.deselect()
            self.plot.invalidate_draw()
            self.plot.request_redraw()
    def _on_unzoom(self):
        self.plot.index_range.high = self.plot.highest_i
        self.plot.index_range.low = self.plot.lowest_i
        self.plot.invalidate_draw()
        self.plot.request_redraw()
    def _on_trace_text(self):
        if self.end != self.start:
            text = self.plot.proj.get_selection_text(self.start,self.end)
            text_view = TextView(text,"%s:[%d:%d]"%(self.plot.proj.filename,self.start,self.end))
            text_view.edit_traits()

    def _selection_updated_delayed(self):
        self.plot.proj.process_stats(self.start,self.end)
        self._timer.Stop()
class tcPlot(BarPlot):
    """custom plot to draw the timechart
    probably not very 'chacotic' We draw the chart as a whole
    """
    # The text of the axis title.
    title = Trait('', Str, Unicode) #May want to add PlotLabel option
    # The font of the title.
    title_font = KivaFont('modern 9')
    # The font of the title.
    title_font_large = KivaFont('modern 15')
    # The font of the title.
    title_font_huge = KivaFont('modern 20')
    # The spacing between the axis line and the title
    title_spacing = Trait('auto', 'auto', Float)
    # The color of the title.
    title_color = ColorTrait("black")
    not_on_screen = List
    on_screen = List
    status = Str
    selection_status = Str
    options = TimeChartOptions()
    range_tools = RangeSelectionTools()
    current_tgid = 0
    row_even = 0
    marks = {}
    redraw_timer = None
    def invalidate(self):
        self.invalidate_draw()
        self.request_redraw()
    def immediate_invalidate(self):
        self.invalidate_draw()
        self.request_redraw_delayed()

    def request_redraw_delayed(self):
        self.redraw_timer.Stop()
        BarPlot.request_redraw(self)
    def request_redraw(self):
        if self.redraw_timer == None:
            self.redraw_timer = timer.Timer(30,self.request_redraw_delayed)
        self.redraw_timer.Start()

    def auto_zoom_y(self):
        if self.value_range.high != self.max_y+1 or self.value_range.low != self.min_y:
            self.value_range.high = self.max_y+1
            self.value_range.low = self.min_y
            self.invalidate_draw()
            self.request_redraw()

    def _gather_timechart_points(self,start_ts,end_ts,y,step):
        low_i = searchsorted(end_ts,self.index_mapper.range.low)
        high_i = searchsorted(start_ts,self.index_mapper.range.high)
        if low_i==high_i:
            return array([])

        start_ts = start_ts[low_i:high_i]
        end_ts = end_ts[low_i:high_i]
        points = column_stack((start_ts,end_ts,
                               zeros(high_i-low_i)+(y+step), ones(high_i-low_i)+(y-step),array(range(low_i,high_i))))
        return points
    def _draw_label(self,gc,label,text,x,y):
        label.text = text
        l_w,l_h = label.get_width_height(gc)
        gc.set_alpha(0.5)
        gc.set_fill_color((1,1,1,1))
        gc.set_line_width(0)
        gc.rect(x, y-l_h/2, l_w, l_h)
        gc.draw_path()
        gc.set_line_width(self.line_width)
        offset = array((x,y-l_h/2))
        gc.translate_ctm(*offset)
        label.draw(gc)
        gc.translate_ctm(*(-offset))
    def _draw_timechart(self,gc,tc,label,base_y):
        bar_middle_y = self.first_bar_y+(base_y+.5)*self.bar_height
        points = self._gather_timechart_points(tc.start_ts,tc.end_ts,base_y,.2)
        overview = None
        if self.options.use_overview:
            if points.size > 500:
                overview = tc.get_overview_ts(self.overview_threshold)
                points = self._gather_timechart_points(overview[0],overview[1],base_y,.2)

        if self.options.remove_pids_not_on_screen and points.size == 0:
            return 0
        if bar_middle_y+self.bar_height < self.y or bar_middle_y-self.bar_height>self.y+self.height:
            return 1 #quickly decide we are not on the screen
        cr,cg,cb,ca = tc.bg_color
        if type(tc) == tcProcess and tc.pid > 0:
            if tc.tgid != self.current_tgid:
                self.current_tgid = tc.tgid
                self.row_even = (self.row_even + 1) % 2
            if self.row_even == 0:
                if cr > .2:
                    cr -= .2
                if cg > .2:
                    cg -= .2
                if cb > .2:
                    cb -= .2
        self._draw_bg(gc,base_y,(cr,cg,cb,ca))
        # we are too short in height, dont display all the labels
        if self.last_label >= bar_middle_y:
            label.text = tc.name
            l_w,l_h = label.get_width_height(gc)
        else:
            l_w,l_h = 0,0
        if points.size != 0:
            # draw the middle line from end of label to end of screen
            if l_w != 0: # we did not draw label because too short on space
                gc.set_alpha(0.2)
                gc.move_to(self.x+l_w,bar_middle_y)
                gc.set_line_dash([5,10])
                gc.line_to(self.x+self.width,bar_middle_y)
                gc.draw_path()
                gc.set_line_dash([0])
            gc.set_alpha(0.5)
            # map the bars start and stop locations into screen space
            lower_left_pts = self.map_screen(points[:,(0,2)])
            upper_right_pts = self.map_screen(points[:,(1,3)])
            bounds = upper_right_pts - lower_left_pts

            if overview: # critical path, we only draw unicolor rects
                #calculate the mean color
                #print points.size
                gc.set_fill_color(get_aggcolor_by_id(get_color_id("overview")))
                gc.set_alpha(.9)
                rects=column_stack((lower_left_pts, bounds))
                gc.rects(rects)
                gc.draw_path()
            else:
                # lets display them more nicely
                rects=column_stack((lower_left_pts, bounds,points[:,(4)]))
                last_t = -1
                gc.save_state()
                for x,y,sx,sy,i in rects:
                    t = tc.types[i]

                    if last_t != t:
                        # only draw when we change color. agg will then simplify the path
                        # note that a path only can only have one color in agg.
                        gc.draw_path()
                        gc.set_fill_color(get_aggcolor_by_id(int(t)))
                        last_t = t
                    gc.rect(x,y,sx,sy)
                # draw last path
                gc.draw_path()
                if tc.has_comments:
                    for x,y,sx,sy,i in rects:
                        if sx<8: # not worth calculatig text size
                            continue
                        label.text = tc.get_comment(i)
                        cl_w,cl_h = label.get_width_height(gc)
                        char_width=cl_w/len(tc.get_comment(i))

                        label.text = tc.get_comment(i)[:int(sx/char_width)]
                        cl_w,cl_h = label.get_width_height(gc)

                        offset = array((x,y+self.bar_height*.6/2-cl_h/2))
                        gc.translate_ctm(*offset)
                        label.draw(gc)
                        gc.translate_ctm(*(-offset))
            if tc.max_latency > 0: # emphase events where max_latency is reached
                ts = tc.max_latency_ts
                if ts.size>0:
                    points = self._gather_timechart_points(ts,ts,base_y,0)
                    if points.size>0:
                        # map the bars start and stop locations into screen space
                        gc.set_alpha(1)
                        lower_left_pts = self.map_screen(points[:,(0,2)])
                        upper_right_pts = self.map_screen(points[:,(1,3)])
                        bounds = upper_right_pts - lower_left_pts
                        rects=column_stack((lower_left_pts, bounds))
                        gc.rects(rects)
                        gc.draw_path()
        if self.last_label >= bar_middle_y:
            self._draw_label(gc,label,tc.name,self.x,bar_middle_y)
            self.last_label = bar_middle_y-8
        return 1
    def _draw_marks(self,gc,marks):
        timestamps = marks.keys()
        timestamps.sort()
        previous=None
        font = self.title_font
        label = Label(text="Dummy",
                      font=font,
                      color=self.title_color,
                      rotate_angle=0)
        yo=self.outer_height
        l_w,l_h = label.get_width_height(gc)
        y=yo-l_h
        # Add white alpha to be more readable
        gc.set_alpha(.8)
        gc.set_fill_color((1,1,1,1))
        gc.set_line_width(0)
        gc.rect(self.x, self.y2, self.width, -l_h-4)
        gc.draw_path()
        gc.set_line_width(self.line_width)
        gc.set_alpha(0.5)
        for ts in timestamps:
            x = self.map_screen(array((ts,0)))[0]
            if previous:
                gc.move_to(previous,y)
                if 10 < x-previous:
                    gc.line_to(previous+5,y+3)
                    gc.line_to(previous+5,y-3)
                    gc.line_to(previous,y)
                gc.line_to(x,y)
                if 10 < x-previous:
                    gc.line_to(x-5,y-3)
                    gc.line_to(x-5,y+3)
                    gc.line_to(x,y)
                label.text = "%s" % _pretty_time(ts - previous_ts)
                l_w,l_h = label.get_width_height(gc)

                if l_w/2 < x-previous:
                    x_label=previous+((x-previous-l_w)/2)
                    offset = array((x_label,y))
                    gc.translate_ctm(*offset)
                    label.draw(gc)
                    gc.translate_ctm(*(-offset))

            gc.move_to(x,0)
            gc.line_to(x,yo)
            previous = x
            previous_ts = ts
        gc.draw_path()

    def _draw_freqchart(self,gc,tc,label,y):
        self._draw_bg(gc,y,tc.bg_color)
        low_i = searchsorted(tc.start_ts,self.index_mapper.range.low)
        high_i = searchsorted(tc.start_ts,self.index_mapper.range.high)

        if low_i>0:
            low_i -=1
        if high_i<len(tc.start_ts):
            high_i +=1
        if low_i>=high_i-1:
            return array([])
        start_ts = tc.start_ts[low_i:high_i-1]
        end_ts = tc.start_ts[low_i+1:high_i]
        values = (tc.types[low_i:high_i-1]/(float(tc.max_types)))+y
        starts = column_stack((start_ts,values))
        ends = column_stack((end_ts,values))
        starts = self.map_screen(starts)
        ends = self.map_screen(ends)
        gc.begin_path()
        gc.line_set(starts, ends)
        gc.stroke_path()
        for i in xrange(len(starts)):
            x1,y1 = starts[i]
            x2,y2 = ends[i]
            sx = x2-x1
            if sx >8:
                label.text = str(tc.types[low_i+i])
                l_w,l_h = label.get_width_height(gc)
                if l_w < sx:
                    if x1<0:x1=0
                    offset = array((x1,y1))
                    gc.translate_ctm(*offset)
                    label.draw(gc)
                    gc.translate_ctm(*(-offset))
    def _draw_ipc(self,gc,processes_y):
        low_i = searchsorted(self.proj.ipc_events['time_sender'],self.index_mapper.range.low)
        high_i = searchsorted(self.proj.ipc_events['time_sender'],self.index_mapper.range.high)
        gc.set_fill_color((0,0,0,0))
        for i in xrange(low_i,high_i):
            sender,receiver,ts_sender,ts_receiver,color = self.proj.ipc_events[i]
            if processes_y.has_key(receiver) and processes_y.has_key(sender):
                gc.set_stroke_color(color)
                y1 = processes_y[receiver]
                y2 = processes_y[sender]
                x,y = self.map_screen(array((ts_receiver,y1)))
                gc.move_to(x,y-5)
                gc.line_to(x,y)
                y2 = processes_y[sender]
                x,y = self.map_screen(array((ts_sender,y2)))
                gc.line_to(x,y)
                gc.line_to(x,y+5)
                x,y = self.map_screen(array(((ts_receiver+ts_sender)/2,(y1+y2)/2)))
                if y1 > y2:
                    y+=5
                    dy=-5
                else:
                    y-=5
                    dy=+5
                gc.move_to(x,y)
                gc.line_to(x-3,y+dy)
                gc.move_to(x,y)
                gc.line_to(x+3,y+dy)
                gc.draw_path()
        gc.set_stroke_color(self.line_color_)

    def _draw_bg(self,gc,y,color):
        gc.set_alpha(1)
        gc.set_line_width(0)
        gc.set_fill_color(color)
        this_bar_y = self.map_screen(array((0,y)))[1]
        gc.rect(self.x, this_bar_y, self.width, self.bar_height)
        gc.draw_path()
        gc.set_line_width(self.line_width)
        gc.set_alpha(0.5)

    def _draw_plot(self, gc, view_bounds=None, mode="normal"):
        gc.save_state()
        gc.clip_to_rect(self.x, self.y, self.width, self.height)
        gc.set_antialias(1)
        gc.set_stroke_color(self.line_color_)
        gc.set_line_width(self.line_width)
        self.first_bar_y = self.map_screen(array((0,0)))[1]
        self.last_label = self.height+self.y
        self.bar_height = self.map_screen(array((0,1)))[1]-self.first_bar_y
        self.max_y = y = self.proj.num_cpu*2+self.proj.num_process-1
        if self.bar_height>15:
            font = self.title_font_large
        else:
            font = self.title_font
        label = Label(text="",
                      font=font,
                      color=self.title_color,
                      rotate_angle=0)
        # we unmap four pixels on screen, and find the nearest greater power of two
        # this by rounding the log2, and then exponentiate again
        # as the overview data is cached, this avoids using too much memory
        four_pixels = self.index_mapper.map_data(array((0,4)))
        self.overview_threshold = 1<<int(log(1+int(four_pixels[1] - four_pixels[0]),2))

        for i in xrange(len(self.proj.c_states)):
            tc = self.proj.c_states[i]
            if self.options.show_c_states:
                self._draw_timechart(gc,tc,label,y)
                y-=1
            tc = self.proj.p_states[i]
            if self.options.show_p_states:
                self._draw_freqchart(gc,tc,label,y)
                y-=1
        processes_y = {0xffffffffffffffffL:y+1}
        not_on_screen = []
        on_screen = []
        self.row_even = 0
        for tc in self.proj.processes:
            if self.options.show_sysusertag:
                if tc.process_type == "tracing_mark_write_sync" or tc.process_type == "tracing_mark_write_async":
                    continue
            else:
                if tc.process_type == "tracing_mark_write_sysutag":
                    continue
            if tc.show==False:
                continue
            processes_y[(tc.comm,tc.pid)] = y+.5
            if self._draw_timechart(gc,tc,label,y) or not self.options.remove_pids_not_on_screen:
                y-=1
                on_screen.append(tc)
            else:
                not_on_screen.append(tc)
        self.not_on_screen = not_on_screen
        self.on_screen = on_screen
        if self.options.show_ipc_events:
            self._draw_ipc(gc,processes_y)
        if self.options.show_marks:
            self._draw_marks(gc,self.marks)

        message = ""
        if self.proj.filename=="dummy":
            message = "please load a trace file in the 'file' menu"
        elif len(self.proj.processes)==0:
            message = "no processes??! is your trace empty?"
        if message:
            label.text = message
            label.font = self.title_font_huge
            gc.translate_ctm(100,(self.y+self.height)/2)
            label.draw(gc)

        gc.restore_state()
        self.min_y = y
        if self.options.auto_zoom_y:
            self.options.auto_zoom_timer.Start()
    def _on_hide_others(self):
        for i in self.not_on_screen:
            i.show = False
        self.invalidate_draw()
        self.request_redraw()
    def _on_hide_onscreen(self):
        for i in self.on_screen:
            i.show = False
        self.invalidate_draw()
        self.request_redraw()

def create_timechart_container(project):
    """ create a vplotcontainer which connects all the inside plots to synchronize their index_range """

    # find index limits
    low = 1<<64
    high = 0
    for i in xrange(len(project.c_states)):
        if len(project.c_states[i].start_ts):
            low = min(low,project.c_states[i].start_ts[0])
            high = max(high,project.c_states[i].end_ts[-1])
        if len(project.p_states[i].start_ts):
            low = min(low,project.p_states[i].start_ts[0])
            high = max(high,project.p_states[i].start_ts[-1])
    for tc in project.processes:
        if len(tc.start_ts):
            low = min(low,tc.start_ts[0])
            high = max(high,tc.end_ts[-1])
    project.process_stats(low,high)
    if low > high:
        low=0
        high=1
    # we have the same x_mapper/range for each plots
    index_range = DataRange1D(low=low, high=high)
    index_mapper = LinearMapper(range=index_range,domain_limit=(low,high))
    value_range = DataRange1D(low=0, high=project.num_cpu*2+project.num_process)
    value_mapper = LinearMapper(range=value_range,domain_limit=(0,project.num_cpu*2+project.num_process))
    index = ArrayDataSource(array((low,high)), sort_order="ascending")
    plot = tcPlot(index=index,
                         proj=project, bgcolor="white",padding=(0,0,0,20),
                         use_backbuffer = True,
                         fill_padding = True,
                         value_mapper = value_mapper,
                         index_mapper=index_mapper,
                         line_color="black",
                         render_style='hold',
                         line_width=1)
    plot.lowest_i = low
    plot.highest_i = high
    project.on_trait_change(plot.invalidate, "plot_redraw")
    project.on_trait_change(plot.invalidate, "selected")
    max_process = 50
    if value_range.high>max_process:
        value_range.low = value_range.high-max_process
    # Attach some tools
    plot.tools.append(tools.myPanTool(plot,drag_button='left'))
    zoom = tools.myZoomTool(component=plot, tool_mode="range", always_on=True,axis="index",drag_button=None, zoom_to_mouse=True,x_max_zoom_factor=float("inf"),x_min_zoom_factor=float("-inf"))
    plot.tools.append(zoom)

    plot.range_selection = tools.myRangeSelection(plot,resize_margin=3)
    plot.tools.append(plot.range_selection)
    plot.overlays.append(RangeSelectionOverlay(component=plot,axis="index",use_backbuffer=True))

    axe = PlotAxis(orientation='bottom',mapper=index_mapper,component=plot)
    plot.underlays.append(axe)
    plot.options.connect(plot)
    plot.range_tools.connect(plot)
    return plot
