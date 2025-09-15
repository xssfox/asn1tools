"""Efficient Packed Encoding Rules (EPER) codec. (Patent 5,638,066)

"""

from operator import attrgetter
from operator import itemgetter
import binascii
import string
import datetime

from ..parser import EXTENSION_MARKER
from . import BaseType, format_bytes, ErrorWithLocation
from . import EncodeError
from . import DecodeError
from . import OutOfDataError
from . import compiler
from . import format_or
from . import restricted_utc_time_to_datetime
from . import restricted_utc_time_from_datetime
from . import restricted_generalized_time_to_datetime
from . import restricted_generalized_time_from_datetime
from .compiler import enum_values_split
from .compiler import enum_values_as_dict
from .compiler import clean_bit_string_value
from .compiler import rstrip_bit_string_zeros
from .ber import encode_real
from .ber import decode_real
from .ber import encode_object_identifier
from .ber import decode_object_identifier
from .permitted_alphabet import NUMERIC_STRING
from .permitted_alphabet import PRINTABLE_STRING
from .permitted_alphabet import IA5_STRING
from .permitted_alphabet import BMP_STRING
from .permitted_alphabet import VISIBLE_STRING
from .per import PermittedAlphabet, AdditionGroup, CompiledType

class Type(BaseType):

    def __init__(self, name, type_name):
        super().__init__(name, type_name)
        self.module_name = None
        self.tag = None
        self.isBitField = False

    def set_size_range(self, minimum, maximum, has_extension_marker):
        pass

    def set_restricted_to_range(self, minimum, maximum, has_extension_marker):
        pass

class KnownMultiplierStringType(Type):

    ENCODING = 'ascii'

    def __init__(self,
                 name,
                 minimum=None,
                 maximum=None,
                 has_extension_marker=False,
                 permitted_alphabet=None):
        super(KnownMultiplierStringType, self).__init__(name,
                                                        self.__class__.__name__)

class Decoder(object):

    def __init__(self, encoded):
        raise NotImplemented

class MembersType(Type):
     # TODO THIS IS FROM PER AND NEEDS TO ADJUSTED

    def __init__(self,
                 name,
                 root_members,
                 additions,
                 type_name):
        super(MembersType, self).__init__(name, type_name)
        self.root_members = root_members
        self.additions = additions
        self.optionals = [
            member
            for member in root_members
            if member.optional or member.default is not None
        ]


class ArrayType(Type):

    def __init__(self,
                 name,
                 element_type,
                 minimum,
                 maximum,
                 has_extension_marker,
                 type_name):
        super(ArrayType, self).__init__(name, type_name)
class Boolean(Type):

    def __init__(self, name):
        super(Boolean, self).__init__(name, 'BOOLEAN')

class Integer(Type):

    def __init__(self, name):
        super(Integer, self).__init__(name, 'INTEGER')
    
class Null(Type):

    def __init__(self, name):
        super(Null, self).__init__(name, 'NULL')

class BitString(Type):

    def __init__(self,
                 name,
                 named_bits,
                 minimum,
                 maximum,
                 has_extension_marker):
        super(BitString, self).__init__(name, 'BIT STRING')

class OctetString(Type):

    def __init__(self, name, minimum, maximum, has_extension_marker):
        super(OctetString, self).__init__(name, 'OCTET STRING')
    
class Enumerated(Type):

    def __init__(self, name, values, numeric):
        super(Enumerated, self).__init__(name, 'ENUMERATED')
    
class Sequence(MembersType):

    def __init__(self,
                 name,
                 root_members,
                 additions):
        super(Sequence, self).__init__(name,
                                       root_members,
                                       additions,
                                       'SEQUENCE')

class SequenceOf(ArrayType):

    def __init__(self,
                 name,
                 element_type,
                 minimum,
                 maximum,
                 has_extension_marker):
        super(SequenceOf, self).__init__(name,
                                         element_type,
                                         minimum,
                                         maximum,
                                         has_extension_marker,
                                         'SEQUENCE OF')

class Set(MembersType):

    def __init__(self,
                 name,
                 root_members,
                 additions):
        super(Set, self).__init__(name,
                                  root_members,
                                  additions,
                                  'SET')
    
class SetOf(ArrayType):

    def __init__(self,
                 name,
                 element_type,
                 minimum,
                 maximum,
                 has_extension_marker):
        super(SetOf, self).__init__(name,
                                    element_type,
                                    minimum,
                                    maximum,
                                    has_extension_marker,
                                    'SET OF')
    

class UTF8String(Type):

    def __init__(self, name):
        super(UTF8String, self).__init__(name, 'UTF8String')
    
class NumericString(KnownMultiplierStringType):

    ALPHABET = bytearray(NUMERIC_STRING.encode('ascii'))
    ENCODE_MAP = {v: i for i, v in enumerate(ALPHABET)}
    DECODE_MAP = {i: v for i, v in enumerate(ALPHABET)}
    PERMITTED_ALPHABET = PermittedAlphabet(ENCODE_MAP,
                                           DECODE_MAP)
    
class PrintableString(KnownMultiplierStringType):

    ALPHABET = bytearray(PRINTABLE_STRING.encode('ascii'))
    ENCODE_MAP = {v: v for v in ALPHABET}
    DECODE_MAP = {v: v for v in ALPHABET}
    PERMITTED_ALPHABET = PermittedAlphabet(ENCODE_MAP,
                                           DECODE_MAP)
    

class IA5String(KnownMultiplierStringType):

    ALPHABET = bytearray(IA5_STRING.encode('ascii'))
    ENCODE_DECODE_MAP = {v: v for v in ALPHABET}
    PERMITTED_ALPHABET = PermittedAlphabet(ENCODE_DECODE_MAP,
                                           ENCODE_DECODE_MAP)


class BMPString(KnownMultiplierStringType):

    ENCODING = 'utf-16-be'
    ALPHABET = BMP_STRING
    ENCODE_DECODE_MAP = {ord(v): ord(v) for v in ALPHABET}
    PERMITTED_ALPHABET = PermittedAlphabet(ENCODE_DECODE_MAP,
                                           ENCODE_DECODE_MAP)


class VisibleString(KnownMultiplierStringType):

    ALPHABET = bytearray(VISIBLE_STRING.encode('ascii'))
    ENCODE_DECODE_MAP = {v: v for v in ALPHABET}
    PERMITTED_ALPHABET = PermittedAlphabet(ENCODE_DECODE_MAP,
                                           ENCODE_DECODE_MAP)


class StringType(Type):
    def __init__(self, name):
        raise NotImplemented
class GeneralString(StringType):

    ENCODING = 'latin-1'


class GraphicString(StringType):

    ENCODING = 'latin-1'


class TeletexString(StringType):

    ENCODING = 'iso-8859-1'


class UniversalString(StringType):

    ENCODING = 'utf-32-be'
    LENGTH_MULTIPLIER = 4

class OffsetAndBitField():
    """
    From EPER: (Part Three FDT-Based System and Protocol Engineer) Efficient Packed Encoding Rules for ASN.1

    Offset Field is required when the following is present:
     - BitString type
     - Sequence/Set which itself includes bit data of an optional or default component
     - Choice type which includes bit data as a choice
     - Sequence/Set includes bit data
    This is because we can't determine how long the bit field will be  

    Offset Field encoding:
    - 0b0 - 1 to 7 bits required use the remaining bits for BIF (Bit Field)
    - 0b10 - 0 bits or 1-63 OCETS then 6 remaining bits is the number of ocets reserved for BIF
    - 0b11 - remaining 6 bits set number of ocets required for Offset field length, and the offset field defines the number  ocets of BIF

    """
    def __init__(self):
        self.off_required = False
        self.__bitCount = 0
        self.__bits = []

    def checkOffRequired(self, type_name: str, members=None):
        if type_name in [
            'BIT STRING',
        ]:
            self.off_required = True
        if (members and [(x.optional or x.has_default) and x.isBitField for x in members]):
            self.off_required = True
    def addBitField(self, bit: bool):
        self.__bits.append(bit)
    def __bytes__(self):
        """
        Return the offset field (if required) and Bit Field (BIF)
        """
        if self.off_required:
            if (    len(self.__bits) == 0 or
                    (len(self.__bits) > 6 and 
                     len(self.__bits) > 8*63
                     )
                ):
                output = bytes([0b10])
            elif len(self.__bits) < 7:
                output = bytes([0b0])
            else:
                output = bytes([0b11])
        else:
            output = b''

        print("NOT REALLY IMPLEMENTED")

        return output

class Choice(Type):

    def __init__(self, name, root_members, additions):
        super(Choice, self).__init__(name, 'CHOICE')


class Compiler(compiler.Compiler):

    # TODO THIS IS FROM PER AND NEEDS TO ADJUSTED

    

    def process_type(self, type_name, type_descriptor, module_name):

        compiled_type = self.compile_type(type_name,
                                          type_descriptor,
                                          module_name)

        return CompiledType(compiled_type)

    def compile_type(self, name, type_descriptor, module_name):
        module_name = self.get_module_name(type_descriptor, module_name)
        type_name = type_descriptor['type']

        if type_name == 'SEQUENCE':
            compiled = Sequence(
                name,
                *self.compile_members(type_descriptor['members'],
                                      module_name))
        elif type_name == 'SEQUENCE OF':
            compiled = SequenceOf(name,
                                  self.compile_type('',
                                                    type_descriptor['element'],
                                                    module_name),
                                  *self.get_size_range(type_descriptor,
                                                       module_name))
        elif type_name == 'SET':
            compiled = Set(
                name,
                *self.compile_members(type_descriptor['members'],
                                      module_name,
                                      sort_by_tag=True))
        elif type_name == 'SET OF':
            compiled = SetOf(name,
                             self.compile_type('',
                                               type_descriptor['element'],
                                               module_name),
                             *self.get_size_range(type_descriptor,
                                                  module_name))
        elif type_name == 'CHOICE':
            compiled = Choice(name,
                              *self.compile_members(
                                  type_descriptor['members'],
                                  module_name,
                                  flat_additions=True))
        elif type_name == 'INTEGER':
            compiled = Integer(name)
        elif type_name == 'REAL':
            compiled = Real(name)
        elif type_name == 'ENUMERATED':
            compiled = Enumerated(name,
                                  self.get_enum_values(type_descriptor,
                                                       module_name),
                                  self._numeric_enums)
        elif type_name == 'BOOLEAN':
            compiled = Boolean(name)
        elif type_name == 'OBJECT IDENTIFIER':
            compiled = ObjectIdentifier(name)
        elif type_name == 'OCTET STRING':
            compiled = OctetString(name,
                                   *self.get_size_range(type_descriptor,
                                                        module_name))
        elif type_name == 'TeletexString':
            compiled = TeletexString(name)
        elif type_name == 'NumericString':
            permitted_alphabet = self.get_permitted_alphabet(type_descriptor)
            compiled = NumericString(name,
                                     *self.get_size_range(type_descriptor,
                                                          module_name),
                                     permitted_alphabet=permitted_alphabet)
        elif type_name == 'PrintableString':
            permitted_alphabet = self.get_permitted_alphabet(type_descriptor)
            compiled = PrintableString(name,
                                       *self.get_size_range(type_descriptor,
                                                            module_name),
                                       permitted_alphabet=permitted_alphabet)
        elif type_name == 'IA5String':
            permitted_alphabet = self.get_permitted_alphabet(type_descriptor)
            compiled = IA5String(name,
                                 *self.get_size_range(type_descriptor,
                                                      module_name),
                                 permitted_alphabet=permitted_alphabet)
        elif type_name == 'BMPString':
            permitted_alphabet = self.get_permitted_alphabet(type_descriptor)
            compiled = BMPString(name,
                                 *self.get_size_range(type_descriptor,
                                                      module_name),
                                 permitted_alphabet=permitted_alphabet)
        elif type_name == 'VisibleString':
            permitted_alphabet = self.get_permitted_alphabet(type_descriptor)
            compiled = VisibleString(name,
                                     *self.get_size_range(type_descriptor,
                                                          module_name),
                                     permitted_alphabet=permitted_alphabet)
        elif type_name == 'GeneralString':
            compiled = GeneralString(name)
        elif type_name == 'UTF8String':
            compiled = UTF8String(name)
        elif type_name == 'GraphicString':
            compiled = GraphicString(name)
        elif type_name == 'UTCTime':
            compiled = UTCTime(name)
        elif type_name == 'UniversalString':
            compiled = UniversalString(name)
        elif type_name == 'GeneralizedTime':
            compiled = GeneralizedTime(name)
        elif type_name == 'DATE':
            compiled = Date(name)
        elif type_name == 'TIME-OF-DAY':
            compiled = TimeOfDay(name)
        elif type_name == 'DATE-TIME':
            compiled = DateTime(name)
        elif type_name == 'BIT STRING':
            compiled = BitString(name,
                                 self.get_named_bits(type_descriptor,
                                                     module_name),
                                 *self.get_size_range(type_descriptor,
                                                      module_name))
        elif type_name == 'ANY':
            compiled = Any(name)
        elif type_name == 'ANY DEFINED BY':
            compiled = Any(name)
        elif type_name == 'NULL':
            compiled = Null(name)
        elif type_name == 'OpenType':
            compiled = OpenType(name)
        elif type_name == 'EXTERNAL':
            compiled = Sequence(
                name,
                *self.compile_members(self.external_type_descriptor()['members'],
                                      module_name))
        elif type_name == 'ObjectDescriptor':
            compiled = ObjectDescriptor(name)
        else:
            if type_name in self.types_backtrace:
                compiled = Recursive(name,
                                     type_name,
                                     module_name)
                self.recursive_types.append(compiled)
            else:
                compiled = self.compile_user_type(name,
                                                  type_name,
                                                  module_name)

        if 'tag' in type_descriptor:
            compiled = self.set_compiled_tag(compiled, type_descriptor)

        if 'restricted-to' in type_descriptor:
            compiled = self.set_compiled_restricted_to(compiled,
                                                       type_descriptor,
                                                       module_name)

        compiled.offset_field = OffsetAndBitField()
        # check if we need BIF
        if compiled is MembersType:
            compiled.offset_field.checkOffRequired(type_name, compiled.root_members)
        else:
            compiled.offset_field.checkOffRequired(type_name)
        return compiled

    def set_compiled_tag(self, compiled, type_descriptor):
        compiled = self.copy(compiled)
        tag = type_descriptor['tag']
        class_prio = CLASS_PRIO[tag.get('class', 'CONTEXT_SPECIFIC')]
        class_number = tag['number']
        compiled.tag = (class_prio, class_number)

        return compiled

    def compile_members(self,
                        members,
                        module_name,
                        sort_by_tag=False,
                        flat_additions=False):
        compiled_members = []
        in_extension = False
        additions = None

        for member in members:
            if member == EXTENSION_MARKER:
                in_extension = not in_extension

                if in_extension:
                    additions = []
            elif in_extension:
                self.compile_extension_member(member,
                                              module_name,
                                              additions,
                                              flat_additions)
            else:
                self.compile_root_member(member,
                                         module_name,
                                         compiled_members)

        if sort_by_tag:
            compiled_members = sorted(compiled_members, key=attrgetter('tag'))

        return compiled_members, additions

    def compile_extension_member(self,
                                 member,
                                 module_name,
                                 additions,
                                 flat_additions):
        if isinstance(member, list):
            if flat_additions:
                for memb in member:
                    compiled_member = self.compile_member(memb,
                                                          module_name)
                    additions.append(compiled_member)
            else:
                compiled_member, _ = self.compile_members(member,
                                                          module_name)
                compiled_group = AdditionGroup('ExtensionAddition',
                                               compiled_member,
                                               None)
                additions.append(compiled_group)
        else:
            compiled_member = self.compile_member(member,
                                                  module_name)
            additions.append(compiled_member)

    def get_permitted_alphabet(self, type_descriptor):
        def char_range(begin, end):
            return ''.join([chr(char)
                            for char in range(ord(begin), ord(end) + 1)])

        if 'from' not in type_descriptor:
            return

        permitted_alphabet = type_descriptor['from']
        value = ''

        for item in permitted_alphabet:
            if isinstance(item, tuple):
                value += char_range(item[0], item[1])
            else:
                value += item

        value = sorted(value)
        encode_map = {ord(v): i for i, v in enumerate(value)}
        decode_map = {i: ord(v) for i, v in enumerate(value)}

        return PermittedAlphabet(encode_map, decode_map)


def compile_dict(specification, numeric_enums=False):
    return Compiler(specification, numeric_enums).process()


def decode_full_length(_data):
    raise DecodeError('Decode length is not supported for this codec.')
