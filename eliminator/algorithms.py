
class UnionSet:
    def __init__(self, n):
        self.father = [i for i in range(n)]
        self.size = [1] * n

    def find(self, x):
        if (x != self.father[x]):
            self.father[x] = self.find(self.father[x])
        return self.father[x]

    def union(self, x, y):
        fx = self.find(x)
        fy = self.find(y)

        if (fx == fy):
            return

        if (self.size[fx] > self.size[fy]):
            t = fx
            fx = fy
            fy = t

        self.father[fx] = fy
        self.size[fy] += self.size[fx]


    def split(self):
        res = {}
        for i in range(len(self.father)):
            fi = self.find(i)
            if fi not in res:
                res[fi] = [i]
            else:
                res[fi].append(i)
        return res


def bin_search(data, key):
    l = 0
    r = len(data) - 1
    mid = (l + r)//2
    while (mid > l):
        if data[mid] == key:
            return mid
        elif data[mid] > key:
            r = mid
        else:
            l = mid
        mid = (l + r)//2
    return mid


if __name__ == "__main__":
    data = [i for i in range(23301)]
    print(bin_search(data, 4601))