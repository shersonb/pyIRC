import json
import inspect
import re
import importlib
import collections
import inspect
import new

from json.decoder import errmsg
from json.encoder import py_encode_basestring_ascii, ESCAPE, ESCAPE_ASCII, HAS_UTF8, ESCAPE_DCT, INFINITY, FLOAT_REPR, encode_basestring, encode_basestring_ascii

FLAGS = re.VERBOSE | re.MULTILINE | re.DOTALL

NUMBER_RE = re.compile(r'(-?(?:0|[1-9]\d*))(\.\d+)?([eE][-+]?\d+)?', FLAGS)
REF_RE = re.compile(
    r'<([A-Z0-9_]+(?:\[[0-9]+(?:,[0-9]+)*\])?(?:\.[A-Z0-9_]+(?:\[[0-9]+(?:,[0-9]+)*\])?)*)>', flags=FLAGS | re.I)
PATH_RE = re.compile(
    r'([A-Z0-9_]+)(?:\[([0-9]+(?:,[0-9]+)*)\])?', flags=FLAGS | re.I)
WHITESPACE = re.compile(r'[ \t\n\r]*', FLAGS)
WHITESPACE_STR = ' \t\n\r'


match_number = NUMBER_RE.match
match_reference = REF_RE.match


datetime_regex = re.compile(
    '\"dt\((\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\)\"')
timedelta_regex = re.compile('\"td\((\d+)\)\"')


    #parse_object = context.parse_object
    #parse_array = context.parse_array
    #parse_string = context.parse_string
    #match_number = NUMBER_RE.match
    #match_reference = REF_RE.match
    #encoding = context.encoding
    #strict = context.strict
    #parse_float = context.parse_float
    #parse_int = context.parse_int
    #parse_constant = context.parse_constant
    #object_hook = context.object_hook
    #object_pairs_hook = context.object_pairs_hook
class ModJSONDecoder(json.JSONDecoder):

    def __init__(self, encoding=None, object_hook=None, parse_float=None,
                 parse_int=None, parse_constant=None, strict=True,
                 object_pairs_hook=None):
        """``encoding`` determines the encoding used to interpret any ``str``
        objects decoded by this instance (utf-8 by default).  It has no
        effect when decoding ``unicode`` objects.

        Note that currently only encodings that are a superset of ASCII work,
        strings of other encodings should be passed in as ``unicode``.

        ``object_hook``, if specified, will be called with the result
        of every JSON object decoded and its return value will be used in
        place of the given ``dict``.  This can be used to provide custom
        deserializations (e.g. to support JSON-RPC class hinting).

        ``object_pairs_hook``, if specified will be called with the result of
        every JSON object decoded with an ordered list of pairs.  The return
        value of ``object_pairs_hook`` will be used instead of the ``dict``.
        This feature can be used to implement custom decoders that rely on the
        order that the key and value pairs are decoded (for example,
        collections.OrderedDict will remember the order of insertion). If
        ``object_hook`` is also defined, the ``object_pairs_hook`` takes
        priority.

        ``parse_float``, if specified, will be called with the string
        of every JSON float to be decoded. By default this is equivalent to
        float(num_str). This can be used to use another datatype or parser
        for JSON floats (e.g. decimal.Decimal).

        ``parse_int``, if specified, will be called with the string
        of every JSON int to be decoded. By default this is equivalent to
        int(num_str). This can be used to use another datatype or parser
        for JSON integers (e.g. float).

        ``parse_constant``, if specified, will be called with one of the
        following strings: -Infinity, Infinity, NaN.
        This can be used to raise an exception if invalid JSON numbers
        are encountered.

        If ``strict`` is false (true is the default), then control
        characters will be allowed inside strings.  Control characters in
        this context are those with character codes in the 0-31 range,
        including ``'\\t'`` (tab), ``'\\n'``, ``'\\r'`` and ``'\\0'``.

        """
        self.encoding = encoding
        self.object_pairs_hook = object_pairs_hook
        self.parse_float = parse_float or float
        self.parse_int = parse_int or int
        self.parse_constant = parse_constant or json.decoder._CONSTANTS.__getitem__
        self.strict = strict
        self.parse_string = json.decoder.scanstring
        self.object_dict_hook = None

    def object_hook(self, d):
        if 'class' in d:
            class_path = d.pop('class')
            modname, clsname = class_path.rsplit(".", 1)
            #module_name = d.pop('__module__')
            module = __import__(modname)
            class_ = getattr(module, clsname)
            args = dict((key.encode('ascii'), value)
                        for key, value in d.items())
            inst = class_(**args)
        else:
            inst = d
        return inst

    def parse_object(self, s_and_end, root, working, _w=WHITESPACE.match, _ws=WHITESPACE_STR):
        s, end = s_and_end
        pairs = []
        pairs_append = pairs.append
        # Use a slice to prevent IndexError from being raised, the following
        # check will raise a more specific ValueError if the string is empty
        nextchar = s[end:end + 1]
        # Normally we expect nextchar == '"'
        if nextchar != '"':
            if nextchar in _ws:
                end = _w(s, end).end()
                nextchar = s[end:end + 1]
            # Trivial empty object
            if nextchar == '}':
                if self.object_dict_hook is not None:
                    result = self.object_dict_hook(working)
                    return result, end + 1
                if self.object_hook is not None:
                    working = self.object_hook(working)
                return working, end + 1
            elif nextchar != '"':
                raise ValueError(errmsg(
                    "Expecting property name enclosed in double quotes", s, end))
        end += 1
        while True:
            key, end = self.parse_string(s, end)

            # To skip some function call overhead we optimize the fast paths where
            # the JSON key separator is ": " or just ":".
            if s[end:end + 1] != ':':
                end = _w(s, end).end()
                if s[end:end + 1] != ':':
                    raise ValueError(errmsg("Expecting ':' delimiter", s, end))
            end += 1

            try:
                if s[end] in _ws:
                    end += 1
                    if s[end] in _ws:
                        end = _w(s, end + 1).end()
            except IndexError:
                pass

            try:
                nextchar = s[end]
            except IndexError:
                raise ValueError(errmsg("Expecting object", s, end))

            if nextchar == '{':
                nextitem = {}
            elif nextchar == '[':
                nextitem = []
            else:
                nextitem = None
            working[key] = nextitem

            try:
                value, end = self.scan_once(s, end, root, nextitem)
            except StopIteration:
                raise ValueError(errmsg("Expecting object", s, end))
            # pairs_append((key, value))
            working[key] = value

            try:
                nextchar = s[end]
                if nextchar in _ws:
                    end = _w(s, end + 1).end()
                    nextchar = s[end]
            except IndexError:
                nextchar = ''
            end += 1

            if nextchar == '}':
                break
            elif nextchar != ',':
                raise ValueError(errmsg("Expecting ',' delimiter", s, end - 1))

            try:
                nextchar = s[end]
                if nextchar in _ws:
                    end += 1
                    nextchar = s[end]
                    if nextchar in _ws:
                        end = _w(s, end + 1).end()
                        nextchar = s[end]
            except IndexError:
                nextchar = ''

            end += 1
            if nextchar != '"':
                raise ValueError(errmsg(
                    "Expecting property name enclosed in double quotes", s, end - 1))
        if self.object_pairs_hook is not None:
            result = self.object_dict_hook(dict)
            return result, end
        if self.object_hook is not None:
            working = self.object_hook(working)
        return working, end

    def parse_array(self, s_and_end, root, working, _w=WHITESPACE.match, _ws=WHITESPACE_STR):
        s, end = s_and_end
        nextchar = s[end:end + 1]
        if nextchar in _ws:
            end = _w(s, end + 1).end()
            nextchar = s[end:end + 1]
        # Look-ahead for trivial empty array
        if nextchar == ']':
            return working, end + 1
        _append = working.append
        while True:
            try:
                nextchar = s[end]
            except IndexError:
                raise ValueError(errmsg("Expecting object", s, end))

            if nextchar == '{':
                nextitem = {}
            elif nextchar == '[':
                nextitem = []
            else:
                nextitem = None
            _append(nextitem)

            try:
                value, end = self.scan_once(s, end, root, nextitem)
            except StopIteration:
                raise ValueError(errmsg("Expecting object", s, end))
            if value is not nextitem:
                del working[-1]
                _append(value)
            nextchar = s[end:end + 1]
            if nextchar in _ws:
                end = _w(s, end + 1).end()
                nextchar = s[end:end + 1]
            end += 1
            if nextchar == ']':
                break
            elif nextchar != ',':
                raise ValueError(errmsg("Expecting ',' delimiter", s, end))
            try:
                if s[end] in _ws:
                    end += 1
                    if s[end] in _ws:
                        end = _w(s, end + 1).end()
            except IndexError:
                pass

        return working, end

    def scan_once(self, string, idx, root, working):
        try:
            nextchar = string[idx]
        except IndexError:
            raise StopIteration

        if nextchar == '"':
            return self.parse_string(string, idx + 1)
        elif nextchar == '{':
            return self.parse_object((string, idx + 1), root, working)
        elif nextchar == '[':
            return self.parse_array((string, idx + 1), root, working)
        elif nextchar == 'n' and string[idx:idx + 4] == 'null':
            return None, idx + 4
        elif nextchar == 't' and string[idx:idx + 4] == 'true':
            return True, idx + 4
        elif nextchar == 'f' and string[idx:idx + 5] == 'false':
            return False, idx + 5
        m = match_number(string, idx)
        if m is not None:
            integer, frac, exp = m.groups()
            if frac or exp:
                res = self.parse_float(integer + (frac or '') + (exp or ''))
            else:
                res = self.parse_int(integer)
            return res, m.end()
        r = match_reference(string, idx)
        if r is not None:
            refname = r.groups()
            obj = root
            for name in refname[0].split("."):
                name, indices = PATH_RE.match(name).groups()
                if name:
                    if type(obj) == dict:
                        obj = obj[name]
                    elif type(obj) == list:
                        obj = obj[int(name)]
                    else:
                        obj = getattr(obj, name)
                if indices:
                    for index in indices.split("."):
                        obj = obj[int(index)]
            return obj, r.end()
        elif nextchar == 'N' and string[idx:idx + 3] == 'NaN':
            return self.parse_constant('NaN'), idx + 3
        elif nextchar == 'I' and string[idx:idx + 8] == 'Infinity':
            return self.parse_constant('Infinity'), idx + 8
        elif nextchar == '-' and string[idx:idx + 9] == '-Infinity':
            return self.parse_constant('-Infinity'), idx + 9
        else:
            raise StopIteration

    def decode(self, s, _w=WHITESPACE.match):
        """Return the Python representation of ``s`` (a ``str`` or ``unicode``
        instance containing a JSON document)

        """
        obj, end = self.raw_decode(s, idx=_w(s, 0).end())
        end = _w(s, end).end()
        if end != len(s):
            raise ValueError(errmsg("Extra data", s, end, len(s)))
        return obj

    def raw_decode(self, s, idx=0):
        """Decode a JSON document from ``s`` (a ``str`` or ``unicode``
        beginning with a JSON document) and return a 2-tuple of the Python
        representation and the index in ``s`` where the document ended.

        This can be used to decode a JSON document from a string that may
        have extraneous data at the end.

        """
        try:
            nextchar = s[idx]
        except IndexError:
            raise ValueError(errmsg("Expecting object", s, idx))

        if nextchar == '{':
            root = {}
        elif nextchar == '[':
            root = []
        else:
            root = None

        try:
            obj, end = self.scan_once(s, idx, root, root)
        except StopIteration:
            raise ValueError("No JSON object could be decoded")
        return obj, end


class ModJSONEncoder(object):

    """Extensible JSON <http://json.org> encoder for Python data structures.

    Supports the following objects and types by default:

    +-------------------+---------------+
    | Python            | JSON          |
    +===================+===============+
    | dict              | object        |
    +-------------------+---------------+
    | list, tuple       | array         |
    +-------------------+---------------+
    | str, unicode      | string        |
    +-------------------+---------------+
    | int, long, float  | number        |
    +-------------------+---------------+
    | True              | true          |
    +-------------------+---------------+
    | False             | false         |
    +-------------------+---------------+
    | None              | null          |
    +-------------------+---------------+

    To extend this to recognize other objects, subclass and implement a
    ``.default()`` method with another method that returns a serializable
    object for ``o`` if possible, otherwise it should call the superclass
    implementation (to raise ``TypeError``).

    """
    item_separator = ', '
    key_separator = ': '

    def __init__(self, skipkeys=False, ensure_ascii=True,
                 check_circular=True, allow_nan=True, sort_keys=False,
                 indent=None, separators=None, encoding='utf-8', default=None):
        """Constructor for JSONEncoder, with sensible defaults.

        If skipkeys is false, then it is a TypeError to attempt
        encoding of keys that are not str, int, long, float or None.  If
        skipkeys is True, such items are simply skipped.

        If *ensure_ascii* is true (the default), all non-ASCII
        characters in the output are escaped with \uXXXX sequences,
        and the results are str instances consisting of ASCII
        characters only.  If ensure_ascii is False, a result may be a
        unicode instance.  This usually happens if the input contains
        unicode strings or the *encoding* parameter is used.

        If check_circular is true, then lists, dicts, and custom encoded
        objects will be checked for circular references during encoding to
        prevent an infinite recursion (which would cause an OverflowError).
        Otherwise, no such check takes place.

        If allow_nan is true, then NaN, Infinity, and -Infinity will be
        encoded as such.  This behavior is not JSON specification compliant,
        but is consistent with most JavaScript based encoders and decoders.
        Otherwise, it will be a ValueError to encode such floats.

        If sort_keys is true, then the output of dictionaries will be
        sorted by key; this is useful for regression tests to ensure
        that JSON serializations can be compared on a day-to-day basis.

        If indent is a non-negative integer, then JSON array
        elements and object members will be pretty-printed with that
        indent level.  An indent level of 0 will only insert newlines.
        None is the most compact representation.  Since the default
        item separator is ', ',  the output might include trailing
        whitespace when indent is specified.  You can use
        separators=(',', ': ') to avoid this.

        If specified, separators should be a (item_separator, key_separator)
        tuple.  The default is (', ', ': ').  To get the most compact JSON
        representation you should specify (',', ':') to eliminate whitespace.

        If specified, default is a function that gets called for objects
        that can't otherwise be serialized.  It should return a JSON encodable
        version of the object or raise a ``TypeError``.

        If encoding is not None, then all input strings will be
        transformed into unicode using that encoding prior to JSON-encoding.
        The default is UTF-8.

        """

        self.skipkeys = skipkeys
        self.ensure_ascii = ensure_ascii
        self.check_circular = check_circular
        self.allow_nan = allow_nan
        self.sort_keys = sort_keys
        self.indent = indent
        if separators is not None:
            self.item_separator, self.key_separator = separators
        if default is not None:
            self.default = default
        self.encoding = encoding

        if self.ensure_ascii:
            self._encoder = encode_basestring_ascii
        else:
            self._encoder = encode_basestring
        if self.encoding != 'utf-8':
            def _encoder(o, _orig_encoder=self._encoder, _encoding=self.encoding):
                if isinstance(o, str):
                    o = o.decode(_encoding)
                return _orig_encoder(o)
            self._encoder = _encoder

    def default(self, o, refs, path):
        """Implement this method in a subclass such that it returns
        a serializable object for ``o``, or calls the base implementation
        (to raise a ``TypeError``).

        For example, to support arbitrary iterators, you could
        implement default like this::

                def default(self, o):
                        try:
                                iterable = iter(o)
                        except TypeError:
                                pass
                        else:
                                return list(iterable)
                        # Let the base class default method raise the TypeError
                        return JSONEncoder.default(self, o)

        """
        if "json" in dir(o) and callable(o.json):
            conf = o.json()

        else:
            conf = collections.OrderedDict()
            conf["class"] = "{o.__class__.__module__}.{o.__class__.__name__}".format(
                **vars())

            if "__init__" in dir(o) and type(o.__init__) == new.instancemethod:
                try:
                    arginspect = inspect.getargspec(o.__init__)
                except:
                    raise TypeError(repr(o) + " is not JSON serializable")

                if arginspect.defaults:
                    requiredargs = arginspect.args[
                        1:len(arginspect.args) - len(arginspect.defaults)]
                    argswithdefaults = arginspect.args[
                        len(arginspect.args) - len(arginspect.defaults):]
                    defaultvalues = arginspect.defaults
                else:
                    requiredargs = arginspect.args[1:]
                    argswithdefaults = []
                    defaultvalues = []

                for key in requiredargs:
                    try:
                        conf[key] = getattr(o, key)
                    except AttributeError:
                        print key
                        print refs.keys()
                        raise TypeError(
                            repr(o) + " is not JSON serializable (Cannot recover required argument '%s')" % key)

                for key, default in zip(argswithdefaults, defaultvalues):
                    try:
                        value = getattr(o, key)
                        if value != default:
                            conf[key] = getattr(o, key)
                    except AttributeError:
                        pass

        if path and not isinstance(conf, (int, long, bool, basestring)) and conf is not None:
            pathstr = str(path[0])
            numindices = []
            for index in path[1:]:
                if type(index) == int:
                    numindices.append(str(index))
                else:
                    if numindices:
                        pathstr += "[%s]" % (",".join(numindices))
                        numindices = []
                    pathstr += ".%s" % index
            if numindices:
                pathstr += "[%s]" % (",".join(numindices))
                numindices = []
            if pathstr not in refs.keys():
                refs[pathstr] = o

        return conf

    def encode(self, o):
        """Return a JSON string representation of a Python data structure.

        >>> JSONEncoder().encode({"foo": ["bar", "baz"]})
        '{"foo": ["bar", "baz"]}'

        """
        # This is for extremely simple cases and benchmarks.
        if isinstance(o, basestring):
            if isinstance(o, str):
                _encoding = self.encoding
                if (_encoding is not None
                        and not (_encoding == 'utf-8')):
                    o = o.decode(_encoding)
            if self.ensure_ascii:
                return encode_basestring_ascii(o)
            else:
                return encode_basestring(o)
        # This doesn't pass the iterator directly to ''.join() because the
        # exceptions aren't as detailed.  The list call should be roughly
        # equivalent to the PySequence_Fast that ''.join() would do.

        chunks = self.iterencode(o, {}, _one_shot=True)
        if not isinstance(chunks, (list, tuple)):
            chunks = list(chunks)
        return ''.join(chunks)

    def iterencode(self, o, refs, _one_shot=False):
        """Encode the given object and yield each string
        representation as available.

        For example::

                for chunk in JSONEncoder().iterencode(bigobject):
                        mysocket.write(chunk)

        """
        if self.check_circular:
            markers = {}
        else:
            markers = None

        def floatstr(o, allow_nan=self.allow_nan,
                     _repr=FLOAT_REPR, _inf=INFINITY, _neginf=-INFINITY):
            # Check for specials.  Note that this type of test is processor
            # and/or platform-specific, so do tests which don't depend on the
            # internals.

            if o != o:
                text = 'NaN'
            elif o == _inf:
                text = 'Infinity'
            elif o == _neginf:
                text = '-Infinity'
            else:
                return _repr(o)

            if not allow_nan:
                raise ValueError(
                    "Out of range float values are not JSON compliant: " +
                    repr(o))

            return text

        # if (_one_shot and c_make_encoder is not None
                # and self.indent is None and not self.sort_keys):
            #_iterencode = c_make_encoder(
                #markers, self.default, _encoder, self.indent,
                #self.key_separator, self.item_separator, self.sort_keys,
                # self.skipkeys, self.allow_nan)
        # else:
            #_iterencode = _make_iterencode(
                #markers, self.default, _encoder, self.indent, floatstr,
                #self.key_separator, self.item_separator, self.sort_keys,
                # self.skipkeys, _one_shot)
        return self._iterencode(o, 0, markers, refs, ())

    def _iterencode(self, o, _current_indent_level, markers, refs, path):
        if isinstance(o, basestring):
            yield self._encoder(o)
        elif o is None:
            yield 'null'
        elif o is True:
            yield 'true'
        elif o is False:
            yield 'false'
        elif isinstance(o, (int, long)):
            yield str(o)
        elif isinstance(o, float):
            yield _floatstr(o)
        else:
            ref = self._iterencode_ref(
                o, _current_indent_level, markers, refs, path)
            if ref:
                yield ref
            elif isinstance(o, (list, tuple)) and "json" not in dir(o):
                for chunk in self._iterencode_list(o, _current_indent_level, markers, refs, path):
                    yield chunk
            elif isinstance(o, dict) and "json" not in dir(o):
                for chunk in self._iterencode_dict(o, _current_indent_level, markers, refs, path):
                    yield chunk
            else:
                if markers is not None:
                    markerid = id(o)
                    if markerid in markers:
                        raise ValueError("Circular reference detected")
                    markers[markerid] = o
                o = self.default(o, refs, path)
                for chunk in self._iterencode(o, _current_indent_level, markers, refs, path):
                    yield chunk
                if markers is not None:
                    del markers[markerid]

    def _iterencode_ref(self, o, _current_indent_level, markers, refs, path):
        for key, value in refs.items():
            if value is o:
                return "<%s>" % key

    def _iterencode_list(self, lst, _current_indent_level, markers, refs, path):
        if path:
            pathstr = str(path[0])
            numindices = []
            for index in path[1:]:
                if type(index) == int:
                    numindices.append(str(index))
                else:
                    if numindices:
                        pathstr += "[%s]" % (",".join(numindices))
                        numindices = []
                    pathstr += ".%s" % index
            if numindices:
                pathstr += "[%s]" % (",".join(numindices))
                numindices = []
            if pathstr not in refs.keys():
                refs[pathstr] = lst

        if not lst:
            yield '[]'
            return
        if markers is not None:
            markerid = id(lst)
            if markerid in markers:
                raise ValueError("Circular reference detected")
            markers[markerid] = lst
        buf = '['
        if self.indent is not None:
            _current_indent_level += 1
            newline_indent = '\n' + \
                (' ' * (self.indent * _current_indent_level))
            separator = self.item_separator + newline_indent
            buf += newline_indent
        else:
            newline_indent = None
            separator = self.item_separator
        first = True
        for (k, value) in enumerate(lst):
            if first:
                first = False
            else:
                buf = separator
            if isinstance(value, basestring):
                yield buf + self._encoder(value)
            elif value is None:
                yield buf + 'null'
            elif value is True:
                yield buf + 'true'
            elif value is False:
                yield buf + 'false'
            elif isinstance(value, (int, long)):
                yield buf + str(value)
            elif isinstance(value, float):
                yield buf + _floatstr(value)
            else:
                ref = self._iterencode_ref(
                    value, _current_indent_level, markers, refs, path)
                if ref and False:
                    yield buf + ref
                else:
                    yield buf
                    if isinstance(value, (list, tuple)) and "json" not in dir(value):
                        chunks = self._iterencode_list(
                            value, _current_indent_level, markers, refs, path + (k,))
                    elif isinstance(value, dict) and "json" not in dir(value):
                        chunks = self._iterencode_dict(
                            value, _current_indent_level, markers, refs, path + (k,))
                    else:
                        chunks = self._iterencode(
                            value, _current_indent_level, markers, refs, path + (k,))
                    for chunk in chunks:
                        yield chunk
        if newline_indent is not None:
            _current_indent_level -= 1
            yield '\n' + (' ' * (self.indent * _current_indent_level))
        yield ']'
        if markers is not None:
            del markers[markerid]

    def _iterencode_dict(self, dct, _current_indent_level, markers, refs, path):
        if path:
            pathstr = str(path[0])
            numindices = []
            for index in path[1:]:
                if type(index) == int:
                    numindices.append(str(index))
                else:
                    if numindices:
                        pathstr += "[%s]" % (",".join(numindices))
                        numindices = []
                    pathstr += ".%s" % index
            if numindices:
                pathstr += "[%s]" % (",".join(numindices))
                numindices = []
            if pathstr not in refs.keys():
                refs[pathstr] = dct

        if not dct:
            yield '{}'
            return
        if markers is not None:
            markerid = id(dct)
            if markerid in markers:
                raise ValueError("Circular reference detected")
            markers[markerid] = dct
        yield '{'
        if self.indent is not None:
            _current_indent_level += 1
            newline_indent = '\n' + \
                (' ' * (self.indent * _current_indent_level))
            item_separator = self.item_separator + newline_indent
            yield newline_indent
        else:
            newline_indent = None
            item_separator = self.item_separator
        first = True
        if self.sort_keys:
            items = sorted(dct.items(), key=lambda kv: kv[0])
        else:
            items = dct.iteritems()
        for key, value in items:
            if isinstance(key, basestring):
                pass
            # JavaScript is weakly typed for these, so it makes sense to
            # also allow them.  Many encoders seem to do something like this.
            elif isinstance(key, float):
                key = _floatstr(key)
            elif key is True:
                key = 'true'
            elif key is False:
                key = 'false'
            elif key is None:
                key = 'null'
            elif isinstance(key, (int, long)):
                key = str(key)
            elif self.skipkeys:
                continue
            else:
                raise TypeError("key " + repr(key) + " is not a string")
            if first:
                first = False
            else:
                yield item_separator
            yield self._encoder(key)
            yield self.key_separator
            if isinstance(value, basestring):
                yield self._encoder(value)
            elif value is None:
                yield 'null'
            elif value is True:
                yield 'true'
            elif value is False:
                yield 'false'
            elif isinstance(value, (int, long)):
                yield str(value)
            elif isinstance(value, float):
                yield _floatstr(value)
            else:
                ref = self._iterencode_ref(
                    value, _current_indent_level, markers, refs, path)
                if ref:
                    yield ref
                else:
                    if isinstance(value, (list, tuple)) and "json" not in dir(value):
                        chunks = self._iterencode_list(
                            value, _current_indent_level, markers, refs, path + (key,))
                    elif isinstance(value, dict) and "json" not in dir(value):
                        chunks = self._iterencode_dict(
                            value, _current_indent_level, markers, refs, path + (key,))
                    else:
                        chunks = self._iterencode(
                            value, _current_indent_level, markers, refs, path + (key,))
                    for chunk in chunks:
                        yield chunk
        if newline_indent is not None:
            _current_indent_level -= 1
            yield '\n' + (' ' * (self.indent * _current_indent_level))
        yield '}'
        if markers is not None:
            del markers[markerid]
