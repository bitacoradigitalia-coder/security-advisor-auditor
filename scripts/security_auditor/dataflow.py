"""Small immutable abstract values. No evaluation of target expressions."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Value:
    sources: tuple = ()
    trace: tuple = ()
    unknown: bool = False
    literals: tuple = ()
    controls: frozenset = frozenset()
    resolved: bool = False
    base: str = ''

    def step(self, text):
        return Value(self.sources, (self.trace + (text,))[-24:], self.unknown,
                     self.literals, self.controls, self.resolved, self.base)

    def control(self, kind):
        return Value(self.sources, self.trace + ('control:' + kind,), self.unknown,
                     self.literals, self.controls | {kind}, self.resolved, self.base)


def merge(*values):
    if not values: return Value(unknown=True)
    controls = set(values[0].controls)
    for value in values[1:]: controls.intersection_update(value.controls)
    sources = tuple(dict.fromkeys(s for v in values for s in v.sources))[:12]
    trace = tuple(dict.fromkeys(s for v in values for s in v.trace))[-24:]
    return Value(sources, trace, any(v.unknown for v in values), (), frozenset(controls))


def join_environments(left, right):
    result = {}
    for name in left.keys() | right.keys():
        a = left.get(name, Value(unknown=True)); b = right.get(name, Value(unknown=True))
        result[name] = a if a == b else merge(a, b)
    return result
