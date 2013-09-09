#
# 31 Aug 2013. Public domain. <cycad@greencams.net>
#
# Loads MBN ROM files into IDA. Loading was taken from Ralekdev's description at:
# http://forum.xda-developers.com/showpost.php?p=29925760
#
# This creates up to segments:
#   Code
#   Signature (optional) - Signature section
#   Cert Chain (optional) - Certificate chain section
#   Tail (optional) - Data between the end of Code Size + Signature Size + Cert Chain Size and Image Size
#   Overlay (optional) - Data between Image Size and the actual end of the input file
#

import idaapi
from idc import *
import os


class MbnHeader:
    """Represents the MBN file header.  It does not do validation on any of the values."""

    SBL_HEADER_SIZE = 0x28
    """Size of the SBL header."""
    
    def __init__(self, rom_data):
        if len(rom_data) < MbnHeader.SBL_HEADER_SIZE: raise ValueError('Invalid ROM header size')
        
        # extract the values from the rom into the class
        (self.load_index,
            self.flash_partition_version,
            self.image_offset,
            self.image_virtual_address,
            self.image_size,
            self.code_size,
            self.signature_virtual_address,
            self.signature_size,
            self.cert_chain_virtual_address,
            self.cert_chain_size) = struct.unpack_from('<LLLLLLLLLL', rom_data)


class MbnRom:
    """Represents the ROM when broken up into its sections."""
    def __init__(self, rom_data):
        # parse the header
        self.header = MbnHeader(rom_data)

        # pull out the image data as it would be loaded from the rom
        image_start = self.header.image_offset + MbnHeader.SBL_HEADER_SIZE
        self.image = rom_data[image_start:image_start + self.header.image_size]

        # pull out the overlay, too
        self.overlay_data = rom_data[image_start + self.header.image_size:]
        if len(self.overlay_data) == 0: self.overlay_data = None
        else: self.overlay_base = self.header.image_virtual_address + self.header.image_size
        
        # some simple sanity checking
        if len(self.image) == 0: raise ValueError('Invalid ROM image size')

        #
        # XXX: This assumes the sections are packed together and then loaded in a
        # specific order in the ROM image. I have no actual idea if that's true
        # or consistent, although it seems to be emperically.
        #
        # Maybe these should be loaded/unpacked in the order of their load addresses?
        #
        
        # load the code section
        self.code_base = self.header.image_virtual_address
        code_size = self.header.code_size
        self.code_data = self.image[:code_size]

        # create the signature segment
        sig_size = self.header.signature_size
        self.sig_data = None
        if sig_size > 0:
            sig_base = self.header.signature_virtual_address
            self.sig_data = self.image[code_size:code_size + sig_size]
            self.sig_base = sig_base
        
        # create the cert chain segment
        cert_size = self.header.cert_chain_size
        self.cert_data = None
        if cert_size > 0:
            cert_base = self.header.cert_chain_virtual_address
            self.cert_data = self.image[code_size + sig_size:code_size + sig_size + cert_size]
            self.cert_base = cert_base

        # create the tail (data after code + sig + certs, but not part of the overlay)
        tail_size = len(self.image) - (code_size + sig_size + cert_size)
        self.tail_data = None
        if tail_size > 0:
            self.tail_base = self.code_base + code_size + sig_size + cert_size
            self.tail_data = self.image[code_size + sig_size + cert_size:]



def AddSegment(name, base_address, data):
    """Add a segment to the IDB with some basic options set for convenience."""
    s = idaapi.segment_t()

    s.startEA = base_address
    s.endEA = base_address + len(data)

    s.bitness = 1 # 32-bit

    s.align = idaapi.saRelByte
    s.comb = idaapi.scPub

    s.sel = idaapi.setup_selector(0)

    idaapi.add_segm_ex(s, name, None, idaapi.ADDSEG_NOSREG | idaapi.ADDSEG_OR_DIE)
    idaapi.mem2base(data, base_address)


def AddIdbComment(image_base, key, value=None):
    """Print out comments in key/value columns, or just a string if no value is given.

    Non-string values for 'value' are converted to 8-digit hex."""
    if value is None:
        idaapi.describe(image_base, True, key)
    else:
        if type(value) != str: value = '0x%08X' % value
        idaapi.describe(image_base, True, '%-24s %s' % (key + ':', value))


def accept_file(li, n):
    if n > 0: return 0

    # make sure the header can be read before accepting
    try:
        rom = MbnRom(li.read(li.size()))
        return {'format': 'MBN ROM', 'options': 1} # accept the file
    except Exception as e:
        # input must be malformed
        return 0


def load_file(li, neflags, format):
    
    # set the processor type and enable 'metaarm' so ida disassembles all instructions
    idaapi.set_processor_type('arm', idaapi.SETPROC_ALL | idaapi.SETPROC_FATAL)
    idc.ChangeConfig('ARM_DEFAULT_ARCHITECTURE = metaarm')

    # rewind the input file and read its contents
    li.seek(0)
    rom_data = li.read(li.size())
    
    # for some reason this doesnt work, so we end up with this
    #rom_name = li.filename().split('.')[0]
    rom_name = ''
    while rom_name == '':
        rom_name = AskStr('', "Enter the input file's basename:")
    if rom_name is None: rom_name = 'rom'

    while True:
        rom_name = os.path.basename(rom_name).split('.')[0]

        # read the rom, letting exceptions fall through to ida's exception handler
        rom = MbnRom(rom_data)

        # for convenience
        image_base = rom.header.image_virtual_address

        # create the segments
        AddSegment('%s_code' % rom_name, rom.code_base, rom.code_data)
        if rom.sig_data is not None: AddSegment('%s_sig' % rom_name, rom.sig_base, rom.sig_data)
        if rom.cert_data is not None: AddSegment('%s_cert' % rom_name, rom.cert_base, rom.cert_data)
        if rom.tail_data is not None: AddSegment('%s_tail' % rom_name, rom.tail_base, rom.tail_data)
        if rom.overlay_data is not None: AddSegment('%s_overlay' % rom_name, rom.overlay_base, rom.overlay_data)

        # mark the entry point as being the first byte of the loaded image
        idaapi.add_entry(rom.code_base, rom.code_base, '%s_start' % rom_name, 1)

        # make some comments for usability
        AddIdbComment(image_base, 'ROM: %s' % rom_name)
        AddIdbComment(image_base, '')
        AddIdbComment(image_base, 'Load Index', rom.header.load_index)
        AddIdbComment(image_base, 'Flash Partition Version', rom.header.flash_partition_version)
        AddIdbComment(image_base, 'Image File Offset', rom.header.image_offset + MbnHeader.SBL_HEADER_SIZE)
        AddIdbComment(image_base, 'Image VA', rom.header.image_virtual_address)
        AddIdbComment(image_base, 'Image Size', rom.header.image_size)
        AddIdbComment(image_base, 'Code VA', rom.header.code_size)
        AddIdbComment(image_base, 'Signature VA', rom.header.signature_virtual_address)
        AddIdbComment(image_base, 'Signature Size', rom.header.signature_size)
        AddIdbComment(image_base, 'Cert Chain VA', rom.header.cert_chain_virtual_address)
        AddIdbComment(image_base, 'Cert Chain Size', rom.header.cert_chain_size)

        # give the opportunity to keep loading mbn files into the address space
        rom_name = AskFile(0, '*.mbn', 'Choose the next ROM filename to load, or click Cancel to continue')
        if rom_name is None:
            break
        else:
            rom_data = open(rom_name, 'rb').read()

    return 1

