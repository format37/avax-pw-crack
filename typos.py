import string

from collections import deque


def insertions(a, b, lowercase=True):
    return string.ascii_lowercase if lowercase else string.ascii_uppercase


def substitutions(x, lowercase=True):
    return string.ascii_lowercase if lowercase else string.ascii_uppercase


def concat(*tokens):
    return "".join(tokens)


def generate_insertions(s, lowercase=True):
    for i in range(len(s)):
        xs = insertions(s[i-1:i], s[i:i+1], lowercase=lowercase)
        yield from (concat(s[:i], x, s[i:]) for x in xs)


def generate_substitutions(s, lowercase=True):
    for i in range(len(s)):
        xs = substitutions(s[i], lowercase=lowercase)
        yield from (concat(s[:i], x, s[i+1:]) for x in xs)


def generate_transpositions(s):
    return (concat(s[:i], s[i+1], s[i], s[i+2:]) for i in range(len(s) - 1))


def generate_deletions(s):
    for i in range(len(s)):
        yield concat(s[:i], s[i+1:])


class Typos(object):
    def __init__(self, root, max_edit_distance=None, visited=None, lowercase=True):
        self.root = root
        self.visited = visited or set()
        self.frontier = deque([(0, root)])
        self.max_edit_distance = max_edit_distance
        self.lowercase = lowercase

    def __iter__(self):
        if self.visited and not self.frontier:
            return iter(self.visited)

        def neighbors(s):
            yield from generate_deletions(s)
            yield from generate_insertions(s, lowercase=self.lowercase)
            yield from generate_substitutions(s, lowercase=self.lowercase)
            yield from generate_transpositions(s)

        def prune(d, s):
            if self.max_edit_distance and d > self.max_edit_distance:
                return True

            if s in self.visited:
                return True

            return False

        while self.frontier:
            d, s = self.frontier.popleft()

            self.visited.add(s)
            yield s

            self.frontier.extend((d+1, n) for n in neighbors(s) if not prune(d+1,n))
