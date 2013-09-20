#import timechart.colors as colors
import colors
from enthought.traits.ui.table_column   import ObjectColumn, ExpressionColumn
from enthought.traits.ui.api import TableEditor

# we subclass ObjectColumn to be able to change the text color depending of whether the Process is shown
class coloredObjectColumn(ObjectColumn):
    def get_text_color(self,i):
        if i.show:
            return colors.get_color_by_name("shown_process")
        else:
            return  colors.get_color_by_name("hidden_process")
    def get_cell_color(self,i):
        return colors.get_color_by_name(i.process_type+"_bg")

class tcTableEditor(TableEditor):
    columns_with_tgid = [
            coloredObjectColumn( name = 'comm',  width = 0.45 ,editable=False),
            coloredObjectColumn( name = 'tgid',  width = 0.10  ,editable=False),
            coloredObjectColumn( name = 'pid',  width = 0.10  ,editable=False),
            coloredObjectColumn( name = 'selection_time', label="stime", width = 0.20, editable=False),
            ExpressionColumn(
                label = 'stime%',
                width = 0.15,
                expression = "'%.2f' % (object.selection_pc)" )
            ]
    columns_without_tgid = [
            coloredObjectColumn( name = 'comm',  width = 0.55 ,editable=False),
            coloredObjectColumn( name = 'pid',  width = 0.10  ,editable=False),
            coloredObjectColumn( name = 'selection_time', label="stime", width = 0.20, editable=False),
            ExpressionColumn(
                label = 'stime%',
                width = 0.15,
                expression = "'%.2f' % (object.selection_pc)" )
            ]

# The definition of the process TableEditor:
process_table_editor = tcTableEditor(
    # Workaround to get columns with good size.
    columns = [ ObjectColumn(), ],
    columns_name = 'process_columns',
    deletable   = False,
    editable   = False,
    sort_model  = False,
    auto_size   = False,
    orientation = 'vertical',
    show_toolbar = False,
    selection_mode = 'rows',
    selected = "selected"
    )
