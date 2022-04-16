import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt

class Visual():
    def __init__(self, adj_list):
        self.adj_list = adj_list
        self.depth = {}

    def cal_depth(self, addr, depth):
        if addr in self.depth:
            return
        self.depth[addr] = depth
        for v in self.adj_list[addr]:
            self.cal_depth(v, depth+1)

    def draw_cfg(self, show_exec_time=False, fold_complex_graph=False):
        from_nodes = []
        to_nodes = []
        start = min(self.adj_list.keys())
        for k in self.adj_list.keys():
            for v in self.adj_list[k]:
                from_nodes.append(hex(k))
                to_nodes.append(hex(v))
        df = pd.DataFrame({'from': from_nodes,
                           'to': to_nodes})
        G = nx.from_pandas_edgelist(df, 'from', 'to', create_using=nx.DiGraph())

        self.depth = {}

        successors = list()
        for k in self.adj_list.values():
            successors += k
        successors = list(set(successors))
        for k in self.adj_list.keys():
            if k not in successors:
                self.cal_depth(k, 1)

        print(self.depth)
        pos = {}
        cnt = {}
        for k in self.depth.keys():
            if self.depth[k] not in cnt:
                cnt[self.depth[k]] = 1
            else:
                cnt[self.depth[k]] += 1
            pos[hex(k)] = (self.depth[k], cnt[self.depth[k]])

        nodes = nx.draw_networkx_nodes(G, pos,
                                       nodelist=pos.keys(),
                                       node_size=1e4,
                                       node_shape='o',
                                       edgecolors='black',
                                       alpha=0.5)

        nx.draw_networkx_labels(G, pos, font_size=12)
        edges = nx.draw_networkx_edges(G, pos, node_size=1.8e4, arrowstyle='->', width=2, arrowsizes=10)
        plt.xlim(0, 4.5)
        plt.ylim(0, 4)
        plt.axis('off')
        plt.show()
