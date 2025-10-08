#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from .utils import Asn1ToolsBaseTest
import asn1tools
import sys
from copy import deepcopy
from asn1tools.codecs import eper
from asn1tools.parser import parse_string

sys.path.append('tests/files')
sys.path.append('tests/files/3gpp')
sys.path.append('tests/files/oma')

from rrc_8_6_0 import EXPECTED as RRC_8_6_0
from s1ap_14_4_0 import EXPECTED as S1AP_14_4_0
from x691_a4 import EXPECTED as X691_A4
from ulp import EXPECTED as OMA_ULP
#from asn1tools.codecs.eper import OffsetAndBitField

class Asn1ToolsPerTest(Asn1ToolsBaseTest):

    def test_fig_11(self):
        # noted that this example is from the patent and the sex coding is not
        # representing the views of the programmer or project
        foo = asn1tools.compile_string(
            """
            US5638066 DEFINITIONS ::= BEGIN
            Employees ::= SEQUENCE OF PersonalRecord
            PersonalRecord ::= SEQUENCE {
                number INTEGER, sex ENUMERATED { male(0), female (1)},
                age INTEGER, firstName PrintableString, lastName
                PrintableString, single BOOLEAN, children ChildInformation
                OPTIONAL}
            ChildInformation ::= SEQUENCE OF SEQUENCE{
                firstName PrintableString, age INTEGER
            }
            END
            """, "eper"
        )

        fig10 = [
            {
                "number": 1,
                "sex": "male",
                "age": 30,
                "firstName": "Taro",
                "lastName": "Yamada",
                "single": False,
                "children": [{"firstName": "Jiro", "age": 3}]
            },
            {
                "number": 2,
                "sex": "female",
                "age": 25,
                "firstName": "Hana",
                "lastName": "Sato",
                "single": True
            }
        ]

        result = bytes(
            [
                0x54, # offset and bit field 

                # 1st record
                    0x02, # number part sequence-of
                    0x01, # number
                    0x1e, # age,
                    
                    0x04, # first name "Taro" - First record
                    0x54,
                    0x61, 
                    0x72, 
                    0x6f,

                    0x06, # lastname "Yamada"
                    0x59,
                    0x61,
                    0x60,
                    0x61, 
                    0x64,
                    0x61,

                        0x01, # number part sequence-of (Child Information)

                        0x04, # first name "Jiro"
                        0x4a, 
                        0x69,
                        0x72,
                        0x6f,

                        0x03, # Age

                # 2nd Personal Record
                
                    0x02, # number
                    0x19, # age

                    0x04, # first name "Hana"
                    0x48,
                    0x61,
                    0x6e,
                    0x61,

                    0x04, # last name "Sato"
                    0x53,
                    0x61,
                    0x74,
                    0x6f


            ]
        )

        datas = [
            ('Employees', fig10, result)
        ]

        for type_name, decoded, encoded in datas:
            self.assert_encode_decode(foo, type_name, decoded, encoded)
    def test_int_systems(self):
            foo = asn1tools.compile_string(
                """
                FDT DEFINITIONS ::= BEGIN
                A ::= SEQUENCE {
                    a [1] INTEGER
                }
                END
                """, "eper"
            )

            example = {
                 "a": 100000,
               
            }

            a_result = bytes(# TODO THESE MIGHT BE THE WRONG BIT ORDER
                 [
                      0b00000000, # tag?
                      0b01_000110, 
                      0b01_000110, 
                      0b1010_0000 
                 ]
            )



            datas = [
                ('A', example, a_result),
            ]

            for type_name, decoded, encoded in datas:
                self.assert_encode_decode(foo, type_name, decoded, encoded)


    def test_p3_fdt_systems(self):
            # These tests are from the Part Three FDT-Based System and Protocol Engineering document examples
            foo = asn1tools.compile_string(
                """
                FDT DEFINITIONS ::= BEGIN
                A ::= SEQUENCE {
                    a [1] INTEGER OPTIONAL,
                    b [2] BOOLEAN OPTIONAL,
                    c [3] INTEGER OPTIONAL,
                    d [4] BOOLEAN OPTIONAL
                }

                C ::= SEQUENCE {
                    a INTEGER,
                    b IA5String OPTIONAL,
                    c BOOLEAN,
                    d INTEGER OPTIONAL
                }

                D ::= SEQUENCE {
                    a INTEGER (0..7),
                    b IA5String (SIZE (1..4)) OPTIONAL,
                    c BOOLEAN,
                    d INTEGER (16) OPTIONAL
                }
                END
                """, "eper"
            )

            example_fig_1 = {
                 "a": 2,
                 "b": True,
                 "c": 1,
                 "d": False
            }

            example = {
                "a": 2,
                "b": "A",
                "c": True,
                "d": 16
            }

            a_result = bytes(# TODO THESE MIGHT BE THE WRONG BIT ORDER
                 [
                      0b0111_1100,
                      0b0000_0001, # This should be value A
                      0b0000_0010  # This should be value C
                      # THERE MIGHT BE AN BUG IN THE EXAMPLE :(
                 ]
            )

            c_result = bytes( # TODO THESE MIGHT BE THE WRONG BIT ORDER
                [
                    0b1110_0000,
                    0b0000_0010,
                    0b0000_0001,
                    0b0100_0001,
                    0b0001_0000
                ]
            )

            d_result = bytes(
                [
                    0b1101_0001,
                    0b0100_0001
                ]
            )


            datas = [
                # ('A', example_fig_1, a_result),
                ('C', example, c_result), #TODO REENABLE THESE TESTS
                ('D', example, d_result)
            ]

            for type_name, decoded, encoded in datas:
                self.assert_encode_decode(foo, type_name, decoded, encoded)

    # def test_offset_field_required(self):
    #     a = OffsetAndBitField()
    #     a.off_required = True
    #     encoded = bytes(a)
        
    #     assert len(encoded) == 1
    # def test_offset_field_not_required(self):
    #     a = OffsetAndBitField()
    #     encoded = bytes(a)
        
    #     assert len(encoded) == 0
    # def test_offset_bitfield(self):
    #     a = OffsetAndBitField()
    #     a.addBitField(True)
    #     encoded = bytes(a)
    #     assert encoded[0] & 0b0000_0001 == 0b0

    #     for x in range(7): # add 7 more bits, to overflow the offset field
    #         a.addBitField(1)
    #     encoded = bytes(True)
    #     assert encoded[0] & 0b0000_0011 == 0b10

    #     for x in range(64*8): # more than 64 ocets of bif
    #         a.addBitField(True)
    #     encoded = bytes(a)
    #     assert encoded[0] & 0b0000_0011 == 0b11
    

    # def test_seq_optional_bit(self):
    #     foo = parse_string(
    #         """
    #         US5638066 DEFINITIONS ::= BEGIN
    #         Employees ::= SEQUENCE OF PersonalRecord
    #         PersonalRecord ::= SEQUENCE {
    #             a BOOLEAN OPTIONAL
    #         }
    #         END
    #         """)
    #     b = eper.Compiler(foo,False)
    #     b.process()
    #     assert b.offset_field.off_required == True

        
    # def test_encode_normal_integer():
    #     integer = eper.Integer("test_number")
    #     data = b"\x41\x00"
    #     # EPER encoding of integer 64
    #     # 1st octet: 01 000001 -- in hex: 41
    #     # 2nd octet: 00 000000 -- in hex: 00
    #     encoder = eper.Encoder()
    #     foo = integer.encode(data, encoder)
    #     #00 011110


if __name__ == '__main__':
    unittest.main()
