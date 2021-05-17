import networkx as nx
import pandas as pd

from bokeh.io import show
from bokeh.models import (Circle, Arrow, NormalHead, EdgesAndLinkedNodes, HoverTool, WheelZoomTool, ResetTool, SaveTool, PanTool,
                          MultiLine, NodesAndLinkedEdges, Plot, Range1d, Label, LabelSet, ColumnDataSource,)
from bokeh.palettes import Spectral4, YlGnBu4
from bokeh.plotting import from_networkx
from bokeh.io import output_notebook

def show_network_graph(tree: pd.DataFrame, layout_function, **kwargs) -> None:

    #tree['subset'] = tree.apply(lambda x: x.path.split("/")[0], axis=1)

    G = nx.DiGraph()
    G = nx.from_pandas_edgelist(
        df=tree,
        source="src_ip",
        target="dst_ip",
        edge_attr=["src_ip", "dst_ip", "app_proto", "dst_key"],
        create_using=nx.DiGraph,
    )

    if pd.NA in G.nodes:
        G.remove_node(pd.NA)
    if "<NA>" in G.nodes:
        G.remove_node("<NA>")

    #for v, data in G.nodes(data=True):
    #    data['subset'] = tree.loc[v]['subset']

    plot = Plot(plot_width=1000, plot_height=1000,
                x_range=Range1d(-1.1,1.1), y_range=Range1d(-1.1,1.1))
    plot.title.text = "Network graph"

    plot.add_tools(
        HoverTool(tooltips=[("SourceIP", "@{src_ip}"), ("DestinationIP", "@{dst_ip}"), ("L7", "@app_proto")]), 
        WheelZoomTool(),
        ResetTool(),
        SaveTool(),PanTool())

    graph_renderer = from_networkx(graph=G, layout_function=layout_function, **kwargs)

    graph_renderer.node_renderer.glyph = Circle(size=15, fill_color=Spectral4[0])
    graph_renderer.node_renderer.selection_glyph = Circle(size=15, fill_color=Spectral4[2])
    graph_renderer.node_renderer.hover_glyph = Circle(size=15, fill_color=Spectral4[1])

    graph_renderer.edge_renderer.glyph = MultiLine(line_color="#CCCCCC", line_alpha=0.8, line_width=5)
    graph_renderer.edge_renderer.selection_glyph = MultiLine(line_color=Spectral4[2], line_width=5)
    graph_renderer.edge_renderer.hover_glyph = MultiLine(line_color=Spectral4[1], line_width=5)

    graph_renderer.selection_policy = NodesAndLinkedEdges()
    graph_renderer.inspection_policy = EdgesAndLinkedNodes()

    positions_df = pd.DataFrame(list(graph_renderer.layout_provider.graph_layout.items()), columns=["src_ip", "Positions"])
    positions_df[['x', 'y']] = pd.DataFrame(positions_df['Positions'].tolist(), columns=['x', 'y'])
    positions_df.set_index("src_ip", inplace=True)
    positions_df.drop('Positions', axis='columns', inplace=True)

    data_df = graph_renderer.edge_renderer.data_source.to_df()
    data_df.set_index("dst_key", inplace=True)

    ttt = pd.merge(left=data_df, right=positions_df, how='left', left_on=['start'], right_on = ['src_ip'])
    ttt = pd.merge(left=ttt, right=positions_df, how='left', left_on=['end'], right_on = ['src_ip'])

    for index, row in ttt.iterrows():
        plot.add_layout(Arrow(end=NormalHead(fill_color=YlGnBu4[1], size=10), line_color=YlGnBu4[1],
                    x_start=row['x_x'], y_start=row['y_x'], x_end=row['x_y'], y_end=row['y_y']))

    plot.add_layout(LabelSet(x='x', y='y', text='src_ip',
                x_offset=5, y_offset=5, source=ColumnDataSource(positions_df), render_mode='canvas'))

    plot.renderers.append(graph_renderer)
    show(plot)