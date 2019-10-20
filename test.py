messages_string = {}

messages_string['midi_connect'] = """
__data:0000000100202530 __ZN4iconL11midiConnectE db  55h ; U    ; DATA XREF: icon::FirmwareUpgradeComponent::MidiInputHandler::sendProgram(void)+158o
__data:0000000100202531                 db  55h ; U
__data:0000000100202532                 db  55h ; U
__data:0000000100202533                 db  55h ; U
__data:0000000100202534                 db  55h ; U
__data:0000000100202535                 db  55h ; U
__data:0000000100202536                 db  55h ; U
__data:0000000100202537                 db  55h ; U
__data:0000000100202538                 db  55h ; U
__data:0000000100202539                 db  55h ; U
__data:000000010020253A                 db  1Dh
__data:000000010020253B                 db    3
__data:000000010020253C                 db    0
__data:000000010020253D                 db  49h ; I
__data:000000010020253E                 db  7Fh ;
__data:000000010020253F                 db    0
__data:0000000100202540 midi_connect_sum db 0                   ; DATA XREF: icon::FirmwareUpgradeComponent::MidiInputHandler::sendProgram(void)+14Fw
__data:0000000100202540                                         ; icon::FirmwareUpgradeComponent::MidiInputHandler::sendProgram(void)+167w
"""

messages_string['midi_erase'] = """
__data:0000000100202550 __ZN4iconL9midiEraseE db  55h ; U       ; DATA XREF: icon::FirmwareUpgradeComponent::MidiInputHandler::sendProgram(void)+2A6o
__data:0000000100202551                 db  55h ; U
__data:0000000100202552                 db  55h ; U
__data:0000000100202553                 db  55h ; U
__data:0000000100202554                 db  55h ; U
__data:0000000100202555                 db  55h ; U
__data:0000000100202556                 db  55h ; U
__data:0000000100202557                 db  55h ; U
__data:0000000100202558                 db  55h ; U
__data:0000000100202559                 db  55h ; U
__data:000000010020255A                 db  1Dh
__data:000000010020255B                 db    3
__data:000000010020255C                 db    0
__data:000000010020255D                 db  49h ; I
__data:000000010020255E                 db    0
__data:000000010020255F byte_10020255F  db 72h                  ; DATA XREF: icon::FirmwareUpgradeComponent::MidiInputHandler::sendProgram(void)+297w
__data:0000000100202560 midi_erase_checksum db 0                ; DATA XREF: icon::FirmwareUpgradeComponent::MidiInputHandler::sendProgram(void)+29Dw
"""

messages_string['midi_write'] = """
__data:0000000100202570 __ZN4iconL9midiWriteE db  55h ; U       ; DATA XREF: icon::FirmwareUpgradeComponent::MidiInputHandler::sendProgram(void)+3FFo
__data:0000000100202570                                         ; icon::FirmwareUpgradeComponent::MidiInputHandler::sendProgram(void)+41Dr ...
__data:0000000100202571                 db  55h ; U
__data:0000000100202572                 db  55h ; U
__data:0000000100202573                 db  55h ; U
__data:0000000100202574                 db  55h ; U
__data:0000000100202575                 db  55h ; U
__data:0000000100202576                 db  55h ; U
__data:0000000100202577                 db  55h ; U
__data:0000000100202578                 db  55h ; U
__data:0000000100202579                 db  55h ; U
__data:000000010020257A                 db  1Dh
__data:000000010020257B                 db    3
__data:000000010020257C                 db    0
__data:000000010020257D                 db  49h ; I
__data:000000010020257E                 db    1
__data:000000010020257F byte_10020257F  db 0                    ; DATA XREF: icon::FirmwareUpgradeComponent::MidiInputHandler::sendProgram(void)+3CEw
__data:000000010020257F                                         ; icon::FirmwareUpgradeComponent::MidiInputHandler::sendProgram(void)+43Ew
__data:0000000100202580 byte_100202580  db 0                    ; DATA XREF: icon::FirmwareUpgradeComponent::MidiInputHandler::sendProgram(void)+411r
"""

messages_string['midi_reset'] = """
__data:0000000100202590 __ZN4iconL9midiResetE db  55h ; U       ; DATA XREF: icon::FirmwareUpgradeComponent::MidiInputHandler::sendProgram(void)+5DEo
__data:0000000100202591                 db  55h ; U
__data:0000000100202592                 db  55h ; U
__data:0000000100202593                 db  55h ; U
__data:0000000100202594                 db  55h ; U
__data:0000000100202595                 db  55h ; U
__data:0000000100202596                 db  55h ; U
__data:0000000100202597                 db  55h ; U
__data:0000000100202598                 db  55h ; U
__data:0000000100202599                 db  55h ; U
__data:000000010020259A                 db  1Dh
__data:000000010020259B                 db    3
__data:000000010020259C                 db    0
__data:000000010020259D                 db  49h ; I
__data:000000010020259E                 db    2
__data:000000010020259F                 db    0
__data:00000001002025A0 byte_1002025A0  db 0                    ; DATA XREF: icon::FirmwareUpgradeComponent::MidiInputHandler::sendProgram(void)+5D5w
__data:00000001002025A0                                         ; icon::FirmwareUpgradeComponent::MidiInputHandler::sendProgram(void)+5EDw
__data:00000001002025A1                 align 8
"""

import re
import collections
import pprint

class IdaDataLine(
    collections.namedtuple(
        'IdaDataLine',
        ('location', 'byte', 'hex_prefix')
    )
):
    @staticmethod
    def from_string(string):
        match = re.search('(:[A-Fa-f0-9]*)? *db *([A-Fa-f0-9]*)(h?)', string)
        return IdaDataLine._make(match.groups()) if match else None

    def to_byte(line_tuple):
        return int(line_tuple.byte, 16) if line_tuple.hex_prefix == 'h' else int(line_tuple.byte)


def ida_copypasta_to_buffer(txt):
    txt_lines     = txt.splitlines()
    parsed_lines  = map(IdaDataLine.from_string, txt_lines)
    nonnull_lines = filter(lambda x: x is not None, parsed_lines)
    all_bytes     = map(IdaDataLine.to_byte, nonnull_lines)
    all_chrs      = map(chr, all_bytes)
    data          = ''.join(all_chrs)
    return data


def split_nibbles(i):
    i = ord(i)
    return (
        ((i & 0x0f)     ),
        ((i % 0xf0) >> 4),
    )

def printer(txt):
    buf = ida_copypasta_to_buffer(txt)
    _ = map(lambda i: hex(ord(i)), buf)
    pprint.pprint(_)
    print "len: ", len(buf), hex(len(buf))

def all():
    print
    print
    print "PROGRAM START"
    print "-------------"

    for t in messages:
        print t
        t = globals().get(t)
        printer(t)
        print

def midi_messages(byte):
    lo, hi = split_nibbles(byte)
    return (0x9f, hi, lo)

def string_to_midi_messages(string):
    buf = ida_copypasta_to_buffer(string)
    return map(midi_messages, buf)

def send_message(port, msg):
    for i in msg:
        print "sending", map(hex, i)
        out.send_message(i)


messages = { name: string_to_midi_messages(string) 
                for name, string in messages_string.iteritems() }

import rtmidi
import time

stage = 0

out = rtmidi.MidiOut()
inp = rtmidi.MidiIn()


fw = open("Platform_M+_V2.05.bin", "rb").read()
fw_messages = map(midi_messages, fw)


def send_command(x):
    print x
    send_message(out, messages[x])
    

def midi_callback(msg, time):
    global stage

    print "midi", msg
    print "time", time

    if stage == 0:
        send_command('midi_connect')
    if stage == 1:
        send_command('midi_erase')
    if stage == 2:
        send_command('midi_write')

        for c in fw_messages:
            out.send_message(c)
            print ".",
        print

    if stage == 3:
        send_command('midi_reset')

    stage += 1

inp.set_callback(midi_callback)

def start():
    print out.get_ports()[4]

    out.open_port(4)
    inp.open_port(4)

    midi_callback("start", "start")

    time.sleep(10)

    print "ENDE"

start()
