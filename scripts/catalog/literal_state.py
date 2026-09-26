"""Read a limited Nuxt/devalue literal wrapper without executing JavaScript.

Only objects, arrays, JSON strings/numbers, literals and function-parameter
references are accepted. Calls, property access, operators and statements fail.
"""
import json
import re


class Reader:
    def __init__(self, text, bindings=None):
        self.text = text
        self.pos = 0
        self.bindings = bindings or {}
        self.nodes = 0

    def space(self):
        while self.pos < len(self.text) and self.text[self.pos].isspace():
            self.pos += 1

    def take(self, token):
        self.space()
        if not self.text.startswith(token, self.pos):
            raise ValueError('unsupported state syntax')
        self.pos += len(token)

    def identifier(self):
        self.space()
        match = re.match(r'[A-Za-z_$][A-Za-z0-9_$]*', self.text[self.pos:])
        if not match:
            raise ValueError('invalid state identifier')
        self.pos += len(match[0])
        return match[0]

    def value(self, depth=0):
        self.nodes += 1
        if depth > 60 or self.nodes > 100000:
            raise ValueError('state too complex')
        self.space()
        ch = self.text[self.pos:self.pos + 1]
        if ch == '"':
            value, end = json.JSONDecoder().raw_decode(self.text, self.pos)
            self.pos = end
            return value
        if ch in ('{', '['):
            object_mode = ch == '{'
            end = '}' if object_mode else ']'
            self.take(ch)
            out = {} if object_mode else []
            self.space()
            while self.text[self.pos:self.pos + 1] != end:
                if object_mode:
                    key = self.value(depth + 1) if self.text[self.pos:self.pos + 1] == '"' else self.identifier()
                    if not isinstance(key, str) or key in out or key in ('__proto__', 'constructor', 'prototype'):
                        raise ValueError('invalid or duplicate state key')
                    self.take(':')
                    out[key] = self.value(depth + 1)
                else:
                    out.append(self.value(depth + 1))
                self.space()
                if self.text[self.pos:self.pos + 1] == end:
                    break
                self.take(',')
                self.space()
            self.take(end)
            return out
        match = re.match(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?', self.text[self.pos:])
        if match:
            self.pos += len(match[0])
            return json.loads(match[0])
        name = self.identifier()
        if name in ('null', 'true', 'false'):
            return {'null': None, 'true': True, 'false': False}[name]
        if name == 'void':
            self.take('0')
            return None
        if name in self.bindings:
            return self.bindings[name]
        raise ValueError('unbound state value')

    def finish(self):
        self.space()
        if self.pos != len(self.text):
            raise ValueError('unexpected state suffix')


def read_nuxt_literal(script):
    if len(script) > 2_000_000:
        raise ValueError('state too large')
    match = re.fullmatch(r'\s*window\.__NUXT__=\(function\(([A-Za-z0-9_$,]*)\)\{return (.*)\}\((.*)\)\);\s*',
                         script, re.S)
    if not match:
        raise ValueError('unsupported state wrapper')
    names = match[1].split(',') if match[1] else []
    if len(set(names)) != len(names):
        raise ValueError('duplicate state parameter')
    args = Reader('[' + match[3] + ']')
    values = args.value()
    args.finish()
    if len(values) != len(names):
        raise ValueError('state argument mismatch')
    reader = Reader(match[2], dict(zip(names, values)))
    result = reader.value()
    reader.finish()
    return result
