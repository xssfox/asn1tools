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
from .per import PermittedAlphabet, AdditionGroup

class CompiledType(compiler.CompiledType):

    def encode(self, data):
        encoder = Encoder()
        try:
            self._type.encode(data, encoder)
        except ErrorWithLocation as e:
            # Add member location
            e.add_location(self._type)
            raise e

        return encoder.as_bytearray()

    def decode(self, data):
        decoder = Decoder(bytearray(data))
        try:
            return self._type.decode(decoder)
        except ErrorWithLocation as e:
            # Add member location
            e.add_location(self._type)
            raise e


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
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.offset_field = OffsetAndBitField()

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
        # check if we need BIF
        if issubclass(type(compiled), MembersType):
            self.offset_field.checkOffRequired(type_name, compiled.root_members)
        else:
            self.offset_field.checkOffRequired(type_name)

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

class Encoder(object):

    def __init__(self):
        self.number_of_bits = 0
        self.value = 0
        self.chunks_number_of_bits = 0
        self.chunks = []

    def __iadd__(self, other):
        for value, number_of_bits in other.chunks:
            self.append_non_negative_binary_integer(value, number_of_bits)

        self.append_non_negative_binary_integer(other.value,
                                                other.number_of_bits)

        return self

    def reset(self):
        self.number_of_bits = 0
        self.value = 0
        self.chunks_number_of_bits = 0
        self.chunks = []

    def are_all_bits_zero(self):
        return not (any([value for value, _ in self.chunks]) or self.value)

    def number_of_bytes(self):
        return (self.chunks_number_of_bits + self.number_of_bits + 7) // 8

    def offset(self):
        return (len(self.chunks), self.number_of_bits)

    def set_bit(self, offset):
        chunk_offset, bit_offset = offset

        if len(self.chunks) == chunk_offset:
            self.value |= (1 << (self.number_of_bits - bit_offset - 1))
        else:
            chunk = self.chunks[chunk_offset]
            chunk[0] |= (1 << (chunk[1] - bit_offset - 1))

    def align(self):
        self.align_always()

    def align_always(self):
        width = 8 * self.number_of_bytes()
        width -= self.chunks_number_of_bits
        width -= self.number_of_bits
        self.number_of_bits += width
        self.value <<= width

    def append_bit(self, bit):
        """Append given bit.

        """

        self.number_of_bits += 1
        self.value <<= 1
        self.value |= bit

    def append_bits(self, data, number_of_bits):
        """Append given bits.

        """

        if number_of_bits == 0:
            return

        value = int(binascii.hexlify(data), 16)
        value >>= (8 * len(data) - number_of_bits)

        self.append_non_negative_binary_integer(value, number_of_bits)

    def append_non_negative_binary_integer(self, value, number_of_bits):
        """Append given integer value.

        """

        if self.number_of_bits > 4096:
            self.chunks.append([self.value, self.number_of_bits])
            self.chunks_number_of_bits += self.number_of_bits
            self.number_of_bits = 0
            self.value = 0

        self.number_of_bits += number_of_bits
        self.value <<= number_of_bits
        self.value |= value

    def append_bytes(self, data):
        """Append given data.

        """

        self.append_bits(data, 8 * len(data))

    def as_bytearray(self):
        """Return the bits as a bytearray.

        """

        value = 0
        number_of_bits = 0

        for chunk_value, chunk_number_of_bits in self.chunks:
            value <<= chunk_number_of_bits
            value |= chunk_value
            number_of_bits += chunk_number_of_bits

        value <<= self.number_of_bits
        value |= self.value
        number_of_bits += self.number_of_bits

        if number_of_bits == 0:
            return bytearray()

        number_of_alignment_bits = (8 - (number_of_bits % 8))

        if number_of_alignment_bits != 8:
            value <<= number_of_alignment_bits
            number_of_bits += number_of_alignment_bits

        value |= (0x80 << number_of_bits)
        value = hex(value)[4:].rstrip('L')

        return bytearray(binascii.unhexlify(value))

    def append_length_determinant(self, length):
        if length < 128:
            encoded = bytearray([length])
        elif length < 16384:
            encoded = bytearray([(0x80 | (length >> 8)), (length & 0xff)])
        elif length < 32768:
            encoded = b'\xc1'
            length = 16384
        elif length < 49152:
            encoded = b'\xc2'
            length = 32768
        elif length < 65536:
            encoded = b'\xc3'
            length = 49152
        else:
            encoded = b'\xc4'
            length = 65536

        self.append_bytes(encoded)

        return length

    def append_length_determinant_chunks(self, length):
        offset = 0
        chunk_length = length

        while True:
            chunk_length = self.append_length_determinant(chunk_length)

            yield offset, chunk_length

            if chunk_length < 16384:
                break

            offset += chunk_length
            chunk_length = length - offset

    def append_normally_small_non_negative_whole_number(self, value):
        if value < 64:
            self.append_non_negative_binary_integer(value, 7)
        else:
            self.append_bit(1)
            length = (value.bit_length() + 7) // 8
            self.append_length_determinant(length)
            self.append_non_negative_binary_integer(value, 8 * length)

    def append_normally_small_length(self, value):
        if value <= 64:
            self.append_non_negative_binary_integer(value - 1, 7)
        elif value <= 127:
            self.append_non_negative_binary_integer(0x100 | value, 9)
        else:
            raise NotImplementedError(
                'Normally small length number >127 is not yet supported.')

    def append_constrained_whole_number(self,
                                        value,
                                        minimum,
                                        maximum,
                                        number_of_bits):
        _range = (maximum - minimum + 1)
        value -= minimum

        if _range <= 255:
            self.append_non_negative_binary_integer(value, number_of_bits)
        elif _range == 256:
            self.align_always()
            self.append_non_negative_binary_integer(value, 8)
        elif _range <= 65536:
            self.align_always()
            self.append_non_negative_binary_integer(value, 16)
        else:
            self.align_always()
            self.append_non_negative_binary_integer(value, number_of_bits)

    def append_unconstrained_whole_number(self, value):
        number_of_bits = value.bit_length()

        if value < 0:
            number_of_bytes = ((number_of_bits + 7) // 8)
            value = ((1 << (8 * number_of_bytes)) + value)

            if (value & (1 << (8 * number_of_bytes - 1))) == 0:
                value |= (0xff << (8 * number_of_bytes))
                number_of_bytes += 1
        elif value > 0:
            number_of_bytes = ((number_of_bits + 7) // 8)

            if number_of_bits == (8 * number_of_bytes):
                number_of_bytes += 1
        else:
            number_of_bytes = 1

        self.append_length_determinant(number_of_bytes)
        self.append_non_negative_binary_integer(value,
                                                8 * number_of_bytes)

    def __repr__(self):
        return format_bytes(self.as_bytearray())


def compile_dict(specification, numeric_enums=False):
    return Compiler(specification, numeric_enums).process()


def decode_full_length(_data):
    raise DecodeError('Decode length is not supported for this codec.')
