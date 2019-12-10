# Block types
BLOCK_SECTION_HEADER = [ 0x0A, 0x0D, 0x0D, 0x0A ]
BLOCK_INTERFACE_DESCRIPTION = [ 0x00, 0x00, 0x00, 0x01 ]
BLOCK_ENHANCED_PACKET = [ 0x00, 0x00, 0x00, 0x06 ]
BLOCK_SIMPLE_PACKET = [ 0x00, 0x00, 0x00, 0x03 ]
BLOCK_ENHANCED_PACKET = [ 0x00, 0x00, 0x00, 0x06 ]
BLOCK_NAME_RESOLUTION = [ 0x00, 0x00, 0x00, 0x04 ]
BLOCK_INTERFACE_STATISTICS = [ 0x00, 0x00, 0x00, 0x05 ]

# --- Option types ---
# Section header options
OPTION_SH_USER_APPLICATION = 4 # Length: variable, UTF-8 string (NULL terminated) 
# Interface options
OPTION_IF_NAME = 2 # Length: variable, UTF-8 string (NULL terminated)
OPTION_IF_DESCRIPTION = 3 # Length: variable, UTF-8 string (NULL terminated)
OPTION_IF_SPEED = 4 # Length: 8, Bits pers seconds
# Enhanced packet options
OPTION_EPB_FLAGS = 2 # Length = 4

class SectionBlockBody:
    def __init__(self):
        self.byte_order_magic = [ 0x1a, 0x2b, 0x3c, 0x4d ]
        self.version_major = [ 0x00, 0x01 ]
        self.version_minor = [ 0x00, 0x00 ]
        self.section_length = [ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff ] # unspecified
        self.options = []

    def WithApplicationName(self, name):
        AddStringOption(OPTION_SH_USER_APPLICATION, name, self.options)
        return self

    def Get(self):
        return self.byte_order_magic + self.version_major + self.version_minor + self.section_length + self.options

class InterfaceDescriptionBlockBody:
    def __init__(self):
        self.linkType = [ 0x00, 147 ] # LINK_TYPE_NULL
        self.reserved_bits = [ 0x00, 0x00 ]
        self.snap_len = [ 0x00, 0x00, 0x05, 0xdc ] # 1500
        self.options = []

    def WitheName(self, name):
        AddStringOption(OPTION_IF_NAME, name, self.options)
        return self

    def WithDescription(self, desc):
        AddStringOption(OPTION_IF_DESCRIPTION, desc, self.options)
        return self

    def WithSpeed(self, speed):
        AddOption(OPTION_IF_SPEED, 8, speed, self.options)
        return self

    def Get(self):
        return self.linkType + self.reserved_bits + self.snap_len + self.options

class SimplePacketBlockBody:
    def __init__(self, data):
        self.original_length = len(data)
        self.data = data
        
        if self.original_length % 4 != 0:
            self.data.extend([0] * (4 - self.original_length % 4))
        
    def Get(self):
        body = []
        body.extend(Num2Hex(self.original_length, 4))
        body.extend(data)
        return body

class EnhancedPacketBlockBody:
    def __init__(self, data, is_reception):
        self.if_id = [ 0x00, 0x00, 0x00, 0x00 ]
        self.ts_high = [ 0xFF, 0xFF, 0xFF, 0xFF ]
        self.ts_low = [ 0x00, 0x00, 0x00, 0x00 ]
        self.captured_len = Num2Hex(len(data), 4)
        self.original_length = self.captured_len
        self.data = data
        self.options = []
        
        AddOption(OPTION_EPB_FLAGS, 4, 1 if is_reception else 2, self.options)

    def Get(self):
        body = []
        body.extend(self.if_id)
        body.extend(self.ts_high)
        body.extend(self.ts_low)
        body.extend(self.captured_len)
        body.extend(self.original_length)
        body.extend(self.data)
        body.extend(self.options)
        
        return body

def AddBlock(btype, body, output: []):
    enc_body = body.Get()
    total_len = 12 + len(enc_body) # 12 = len(type) + 2 * len(total_len)
    enc_len = Num2Hex(total_len, 4)
    output.extend(btype)
    output.extend(enc_len)
    output.extend(enc_body)
    output.extend(enc_len)

# type - two octects
# length - two octects
# value - value of the option, will be padded to 4 octets
def AddOption(opt_type, opt_len, opt_val, output):
    output.extend(Num2Hex(opt_type, 2))
    output.extend(Num2Hex(opt_len, 2))
    
    if isinstance(opt_val, str):
        output.extend(opt_val.encode())
    elif isinstance(opt_val, int):
        output.extend(Num2Hex(opt_val, opt_len))
    else:
        output.extend(opt_val)

    if opt_len % 4 != 0:
        output.extend([0] * (4 - opt_len % 4))

def AddStringOption(opt_type, string , output):
    AddOption(opt_type, len(string) + 1, string + "\0", output)

def Num2Hex(number, length):
    return(number.to_bytes(length, 'big'))

file_output = open('spinel.pcapng', 'w+b')
output = []
AddBlock(BLOCK_SECTION_HEADER, SectionBlockBody().WithApplicationName("Spinel test section"), output)
AddBlock(BLOCK_INTERFACE_DESCRIPTION, InterfaceDescriptionBlockBody()
.WitheName("Spinel interface")
.WithDescription("TROLOLO")
.WithSpeed(1000000), output)
data = [ 0xa1, 0xb2, 0xc3, 0xc4 ]
AddBlock(BLOCK_SIMPLE_PACKET, SimplePacketBlockBody(data), output)
AddBlock(BLOCK_ENHANCED_PACKET, EnhancedPacketBlockBody(data, True), output)
AddBlock(BLOCK_ENHANCED_PACKET, EnhancedPacketBlockBody(data, False), output)

file_output.write(bytearray(output))