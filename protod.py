#!/usr/bin/env python3

import argparse
import importlib.util
import os
import struct
import sys
from copy import deepcopy
from enum import IntEnum
from functools import reduce
from io import BytesIO
from pathlib import Path
from subprocess import check_output
from types import SimpleNamespace
from typing import Dict, List, Union, Optional

# note: tested against protobuf library version 3.11.3
from google.protobuf.internal import api_implementation
api_implementation._SetType('python')
from google.protobuf import descriptor, text_encoding, text_format
from google.protobuf.empty_pb2 import Empty
from google.protobuf.internal import containers, decoder, encoder, wire_format

TMP_PROTOD_DIR = Path('/tmp/protod/')


def _PrintUnknownFields(self, unknown_fields):
    out = self.out
    for field in unknown_fields:
        out.write(' ' * self.indent)
        out.write(str(field.field_number))
        if field.wire_type == wire_format.WIRETYPE_START_GROUP:
            if self.as_one_line:
                out.write(' < ')
            else:
                out.write(' <\n')
                self.indent += 2

            self._PrintUnknownFields(field.data)

            if self.as_one_line:
                out.write('> ')
            else:
                self.indent -= 2
                out.write(' ' * self.indent + '>\n')
        elif field.wire_type == wire_format.WIRETYPE_LENGTH_DELIMITED:
            try:
                msg, pos = decoder._DecodeUnknownFieldSet(
                    memoryview(field.data), 0, len(field.data))
            except Exception:
                pos = 0
            if pos == len(field.data):
                if self.as_one_line:
                    out.write(' { ')
                else:
                    out.write(' {\n')
                    self.indent += 2
                self._PrintUnknownFields(msg)

                if self.as_one_line:
                    out.write('} ')
                else:
                    self.indent -= 2
                    out.write(' ' * self.indent + '}\n')
            else:
                out.write(': \"')
                out.write(text_encoding.CEscape(field.data, False))
                out.write('\" ' if self.as_one_line else '\"\n')
        else:
            out.write(' (')
            out.write({wire_format.WIRETYPE_VARINT:  'int',
                       wire_format.WIRETYPE_FIXED64: 'f64',
                       wire_format.WIRETYPE_FIXED32: 'f32',
                       }[field.wire_type])
            out.write('): ')
            if field.wire_type == wire_format.WIRETYPE_VARINT:
                out.write(str(field.data))
            elif field.wire_type == wire_format.WIRETYPE_FIXED32:
                out.write(str(struct.unpack('<f', struct.pack('<I', field.data))[0]))
            elif field.wire_type == wire_format.WIRETYPE_FIXED64:
                out.write(str(struct.unpack('<d', struct.pack('<Q', field.data))[0]))
            out.write(' ' if self.as_one_line else '\n')

text_format._Printer._PrintUnknownFields = _PrintUnknownFields

def encode_varint(value):
    bio = BytesIO()
    encoder._EncodeVarint(bio.write, value)
    bio.seek(0)
    return bio.read()

def _MergeField(self, tokenizer, message):
    """Merges a single protocol message field into a message.

    Args:
        tokenizer: A tokenizer to parse the field name and values.
        message: A protocol message to record the data.

    Raises:
        ParseError: In case of text parsing problems.
    """
    message_descriptor = message.DESCRIPTOR
    if (message_descriptor.full_name == text_format._ANY_FULL_TYPE_NAME and
            tokenizer.TryConsume('[')):
        type_url_prefix, packed_type_name = self._ConsumeAnyTypeUrl(tokenizer)
        tokenizer.Consume(']')
        tokenizer.TryConsume(':')
        if tokenizer.TryConsume('<'):
            expanded_any_end_token = '>'
        else:
            tokenizer.Consume('{')
            expanded_any_end_token = '}'
        expanded_any_sub_message = text_format._BuildMessageFromTypeName(packed_type_name, self.descriptor_pool)
        if not expanded_any_sub_message:
            raise text_format.ParseError('Type %s not found in descriptor pool' % packed_type_name)
        while not tokenizer.TryConsume(expanded_any_end_token):
            if tokenizer.AtEnd():
                raise tokenizer.ParseErrorPreviousToken('Expected "%s".' % (expanded_any_end_token,))
            self._MergeField(tokenizer, expanded_any_sub_message)
        message.Pack(expanded_any_sub_message, type_url_prefix=type_url_prefix)
        return

    if tokenizer.TryConsume('['):
        name = [tokenizer.ConsumeIdentifier()]
        while tokenizer.TryConsume('.'):
            name.append(tokenizer.ConsumeIdentifier())
        name = '.'.join(name)

        if not message_descriptor.is_extendable:
            raise tokenizer.ParseErrorPreviousToken(
                'Message type "%s" does not have extensions.' %
                message_descriptor.full_name)
        # pylint: disable=protected-access
        field = message.Extensions._FindExtensionByName(name)
        # pylint: enable=protected-access
        if not field:
            if self.allow_unknown_extension:
                field = None
            else:
                raise tokenizer.ParseErrorPreviousToken(
                    'Extension "%s" not registered. '
                    'Did you import the _pb2 module which defines it? '
                    'If you are trying to place the extension in the MessageSet '
                    'field of another message that is in an Any or MessageSet field, '
                    'that message\'s _pb2 module must be imported as well' % name)
        elif message_descriptor != field.containing_type:
            raise tokenizer.ParseErrorPreviousToken(
                'Extension "%s" does not extend message type "%s".' %
                (name, message_descriptor.full_name))

        tokenizer.Consume(']')

    else:
        name = tokenizer.ConsumeIdentifierOrNumber()
        if self.allow_field_number and name.isdigit():
            number = text_format.ParseInteger(name, True, True)
            field = message_descriptor.fields_by_number.get(number, None)
            if not field and message_descriptor.is_extendable:
                field = message.Extensions._FindExtensionByNumber(number)
        else:
            field = message_descriptor.fields_by_name.get(name, None)

            # Group names are expected to be capitalized as they appear in the
            # .proto file, which actually matches their type names, not their field
            # names.
            if not field:
                field = message_descriptor.fields_by_name.get(name.lower(), None)
                if field and field.type != descriptor.FieldDescriptor.TYPE_GROUP:
                    field = None

            if (field and field.type == descriptor.FieldDescriptor.TYPE_GROUP and
                    field.message_type.name != name):
                field = None

        if not field and not self.allow_unknown_field:
            raise tokenizer.ParseErrorPreviousToken(
                'Message type "%s" has no field named "%s".' %
                (message_descriptor.full_name, name))

    if field:
        if not self._allow_multiple_scalars and field.containing_oneof:
            # Check if there's a different field set in this oneof.
            # Note that we ignore the case if the same field was set before, and we
            # apply _allow_multiple_scalars to non-scalar fields as well.
            which_oneof = message.WhichOneof(field.containing_oneof.name)
            if which_oneof is not None and which_oneof != field.name:
                raise tokenizer.ParseErrorPreviousToken(
                    'Field "%s" is specified along with field "%s", another member '
                    'of oneof "%s" for message type "%s".' %
                    (field.name, which_oneof, field.containing_oneof.name,
                     message_descriptor.full_name))

        if field.cpp_type == descriptor.FieldDescriptor.CPPTYPE_MESSAGE:
            tokenizer.TryConsume(':')
            merger = self._MergeMessageField
        else:
            tokenizer.Consume(':')
            merger = self._MergeScalarField

        if (field.label == descriptor.FieldDescriptor.LABEL_REPEATED and
                tokenizer.TryConsume('[')):
            # Short repeated format, e.g. "foo: [1, 2, 3]"
            if not tokenizer.TryConsume(']'):
                while True:
                    merger(tokenizer, message, field)
                    if tokenizer.TryConsume(']'):
                        break
                    tokenizer.Consume(',')

        else:
            merger(tokenizer, message, field)

    else:  # Proto field is unknown.
        assert (self.allow_unknown_extension or self.allow_unknown_field)
        if not name.isdigit():  # Got a field name we don't recognize
            text_format._SkipFieldContents(tokenizer)
        else:
            # We have an int for a name, which means an unknown field we can parse.
            field_number = int(name)
            if message._unknown_fields == ():
                message._unknown_fields = []
            if tokenizer.TryConsume('('):
                # Has a defined wire type -- varint, fixed32 or fixed64.
                # We are going to treat the fixed types as floating-point numbers,
                # since that's what they usually are.
                wire_type = {'f64': wire_format.WIRETYPE_FIXED64,
                             'f32': wire_format.WIRETYPE_FIXED32,
                             'int': wire_format.WIRETYPE_VARINT}[tokenizer.ConsumeIdentifier()]
                tokenizer.Consume(')')
                tokenizer.Consume(':')
                if wire_type == wire_format.WIRETYPE_VARINT:
                    data = tokenizer.ConsumeInteger()
                    field_bytes = encode_varint(data)
                elif wire_type == wire_format.WIRETYPE_FIXED32:
                    field_bytes = struct.pack('<f', tokenizer.ConsumeFloat())
                    data = struct.unpack('<I', field_bytes)
                else:
                    field_bytes = struct.pack('<d', tokenizer.ConsumeFloat())
                    data = struct.unpack('<Q', field_bytes)

                tag_bytes = struct.pack('B', wire_format.PackTag(field_number, wire_type))
                message.UnknownFields()._add(field_number, wire_type, data)
                message._unknown_fields.append((tag_bytes, field_bytes))
            elif tokenizer.TryConsume(':'):  # String
                tag_bytes = struct.pack('B', wire_format.PackTag(field_number, wire_format.WIRETYPE_LENGTH_DELIMITED))
                string = tokenizer.ConsumeString()
                string_encoded = string.encode('utf-8')
                message.UnknownFields()._add(field_number, wire_format.WIRETYPE_LENGTH_DELIMITED, string_encoded)
                message._unknown_fields.append((tag_bytes, encode_varint(len(string_encoded)) + string_encoded))
            elif tokenizer.TryConsume('<'):  # Group
                group = Empty()
                while not tokenizer.TryConsume('>'):
                    self._MergeField(tokenizer, group)
                message.UnknownFields()._add(field_number, wire_format.WIRETYPE_START_GROUP, group.UnknownFields())
                tag_start = struct.pack('B', wire_format.PackTag(field_number, wire_format.WIRETYPE_START_GROUP))
                tag_end = struct.pack('B', wire_format.PackTag(field_number, wire_format.WIRETYPE_END_GROUP))
                message._unknown_fields.append((tag_start, group.SerializeToString() + tag_end))
            elif tokenizer.TryConsume('{'):  # Message
                nested_message = Empty()
                while not tokenizer.TryConsume('}'):
                    self._MergeField(tokenizer, nested_message)
                serialized = nested_message.SerializeToString()
                message.UnknownFields()._add(field_number, wire_format.WIRETYPE_LENGTH_DELIMITED, serialized)
                tag_bytes = struct.pack('B', wire_format.PackTag(field_number, wire_format.WIRETYPE_LENGTH_DELIMITED))
                message._unknown_fields.append((tag_bytes, encode_varint(len(serialized)) + serialized))
            else:
                raise Exception('Encountered unexpected field data, should not happen')

text_format._Parser._MergeField = _MergeField

class UnknownFieldDefinition:
    '''Base class for the merged and unmerged variants'''
    def __init__(self, fnum: int, ftype: int):
        self.fnum = fnum
        self.ftype = ftype

class UnmergedUnknownFieldDefinition(UnknownFieldDefinition):
    def __init__(self, fnum: int, ftype: int, contents):
        super().__init__(fnum, ftype)
        self.contents = contents  # type: Optional[Dict[int, List[UnknownFieldDefinition]]]

    def __repr__(self):
        def pretty_ufd(ufd, indent=0):
            s = f'{indent*" "}UFD(n={ufd.fnum}, t={ufd.ftype} d={ufd.contents is not None})'
            if ufd.contents:
                for cs in ufd.contents.values():
                    for c in cs:
                        s += f'\n{pretty_ufd(c, indent+2)}'
            return s
        return pretty_ufd(self)

class FieldRule(IntEnum):
    REQUIRED = 1
    OPTIONAL = 2
    REPEATED = 3

class MergedUnknownFieldDefinition(UnknownFieldDefinition):
    def __init__(self, fnum: int, ftype: int, frule: FieldRule, contents):
        super().__init__(fnum, ftype)
        self.frule = frule
        self.contents = contents  # type: Optional[Dict[int, UnknownFieldDefinition]]

    def __repr__(self):
        def pretty_ufd(ufd: MergedUnknownFieldDefinition, indent=0):
            s = f'{indent*" "}UFD(n={ufd.fnum}, t={ufd.ftype}, r={str(ufd.frule)[10:]} d={ufd.contents is not None})'
            if ufd.contents:
                for c in ufd.contents.values():
                    s += f'\n{pretty_ufd(c, indent+2)}'
            return s
        return pretty_ufd(self)

def define(message: Union[containers.UnknownFieldSet, SimpleNamespace]) -> UnmergedUnknownFieldDefinition:
    contents = None
    if message.wire_type == wire_format.WIRETYPE_START_GROUP:
        contents = [define(x) for x in message.data]
    elif message.wire_type == wire_format.WIRETYPE_LENGTH_DELIMITED:  # Determine if this is a string or a message
        try:
            message_contents, pos = decoder._DecodeUnknownFieldSet(
                memoryview(message.data), 0, len(message.data))
            if pos == len(message.data):
                contents = [define(x) for x in message_contents]
        except Exception:
            pass
    if contents is not None:
        contents = {x.fnum: [y for y in contents if y.fnum == x.fnum] for x in contents}
    return UnmergedUnknownFieldDefinition(message.field_number, message.wire_type, contents)

def join_definitions(a: Optional[Dict[int, MergedUnknownFieldDefinition]], b: Optional[Dict[int, MergedUnknownFieldDefinition]]) -> Optional[Dict[int, MergedUnknownFieldDefinition]]:
    if None in [a, b]:  # At least one is a primitive value
        return None

    o = {}  # Both are messages
    for k, (va, vb) in {k: (a.get(k), b.get(k)) for k in list(a.keys()) + list(b.keys())}.items():
        if None in [va, vb]:
            o[k] = deepcopy([va, vb][va is None])
            if o[k].frule == FieldRule.REQUIRED:
                o[k].frule = FieldRule.OPTIONAL
        else:
            o[k] = MergedUnknownFieldDefinition(va.fnum, va.ftype, max(va.frule, vb.frule), join_definitions(va.contents, vb.contents))
    return o

# Merges a single message into itself
def merge_definition(x: UnmergedUnknownFieldDefinition) -> MergedUnknownFieldDefinition:
    if x.contents is None:
        o = None
    else:
        o = {k: MergedUnknownFieldDefinition(v[0].fnum, v[0].ftype, FieldRule.REPEATED if len(v) > 1 else FieldRule.REQUIRED, reduce(join_definitions, map(lambda x: merge_definition(x).contents, v))) for k, v in x.contents.items()}
    return MergedUnknownFieldDefinition(x.fnum, x.ftype, FieldRule.REQUIRED, o)

def render_proto(d: MergedUnknownFieldDefinition, proto_3=False, hist=()) -> str:
    indent = '  ' * len(hist)
    name = 'Unk' + '_'.join(map(str, hist))
    if proto_3:
        rule = 'repeated ' if d.frule == FieldRule.REPEATED else ''
    else:
        rule = f'{str(d.frule)[10:].lower()} '

    if d.contents is None:  # primitive
        type = {wire_format.WIRETYPE_LENGTH_DELIMITED: 'string',
                wire_format.WIRETYPE_VARINT: 'int64',
                wire_format.WIRETYPE_FIXED32: 'float',
                wire_format.WIRETYPE_FIXED64: 'double'
                }[d.ftype]
        return f'{indent}{rule}{type} {name.lower()} = {d.fnum};\n'

    # Either a message or a group
    s = ''
    if d.ftype == wire_format.WIRETYPE_LENGTH_DELIMITED and d.fnum == 0:
        s += f'syntax = "proto{proto_3 + 2}";\n\n'

    if d.ftype == wire_format.WIRETYPE_LENGTH_DELIMITED:
        s += f'{indent}message {name} {{\n'
    else:
        s += f'{indent}{rule}group {name} = {d.fnum} {{\n'

    for x in d.contents.values():
        s += render_proto(x, proto_3, hist + (x.fnum, ))

    s += f'{indent}}}\n'

    if d.ftype == wire_format.WIRETYPE_LENGTH_DELIMITED and d.fnum != 0:
        s += f'{indent}{rule}{name} {name.lower()} = {d.fnum};\n'

    return s

def parse_args():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--decode_raw', action='store_true')
    mode.add_argument('--encode_raw', action='store_true')
    mode.add_argument('--encode', nargs=2, metavar=('MESSAGE', 'PROTOFILE'))
    mode.add_argument('--decode', nargs=2, metavar=('MESSAGE', 'PROTOFILE'))
    parser.add_argument('--proto_out', choices=['2', '3'])
    return parser.parse_known_args()

def main():
    args, protoc_args = parse_args()
    if args.decode_raw or args.encode_raw:
        message = Empty()
    else:
        message_name, protofile = args.encode or [] + args.decode or []
        protofile = Path(protofile)
        os.makedirs(str(TMP_PROTOD_DIR), exist_ok=True)
        check_output(['protoc', f'--python_out={TMP_PROTOD_DIR}'] + protoc_args + [str(protofile)])
        pb2_path = TMP_PROTOD_DIR / (protofile.with_suffix('').name + '_pb2.py')
        spec = importlib.util.spec_from_file_location(protofile.with_suffix('').name, pb2_path)
        pb2 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pb2)
        message = getattr(pb2, message_name)()

    if args.decode_raw or args.decode:
        message.ParseFromString(sys.stdin.buffer.read())
    else:
        text_format.Parse(sys.stdin.read(), message, allow_field_number=True, allow_unknown_field=True)
    if args.proto_out:
        unf_like = SimpleNamespace()
        unf_like.wire_type = wire_format.WIRETYPE_LENGTH_DELIMITED
        unf_like.data = message.SerializeToString()
        unf_like.field_number = 0
        print(render_proto(merge_definition(define(unf_like)), args.proto_out == '3'), end='')
    elif args.decode_raw or args.decode:
        print(text_format.MessageToString(message, print_unknown_fields=True), end='')
    else:
        sys.stdout.buffer.write(message.SerializeToString())


if __name__ == '__main__':
    main()
