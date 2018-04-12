import datetime
import struct


def as_signed_le(bs):
    if len(bs) <= 0 or len(bs) > 8:
        raise ValueError()

    signed_format = {1: 'b', 2: 'h', 4: 'l', 8: 'q'}

    fill = b'\xFF' if ((bs[-1] & 0x80) >> 7) == 1 else b'\x00'

    while len(bs) not in signed_format:
        bs = bs + fill

    return struct.unpack('<' + signed_format[len(bs)], bs)[0]


def istat_ntfs(f, address, sector_size=512, offset=0):
    data = f.read()
    data = data[sector_size * offset:]
    result = []
    bytes_per_sector = as_signed_le(data[11:13])
    sectors_per_cluster = as_signed_le(data[13:14])
    bytes_per_cluster = bytes_per_sector * sectors_per_cluster
    mft_cluster = as_signed_le(data[48:56])
    mft_start = bytes_per_cluster * mft_cluster
    mft_entry_size = as_signed_le(data[64:65])
    entry_start = 1024 * address #File Size 1,024 due to project specifications
    entry_data = data[mft_start + entry_start:]
    fixup_array_offset = as_signed_le(entry_data[4:6])
    fixup_array_entries = as_signed_le(entry_data[6:8])
    #Handle Fixup Array
    fixup_array_value = entry_data[fixup_array_offset:fixup_array_offset + 2]
    if fixup_array_value == entry_data[510:512] and fixup_array_value == entry_data[1022:1024]:
        entry_data = bytearray(entry_data)
        entry_data[510:512] = entry_data[fixup_array_offset + 2:fixup_array_offset + 4]
        entry_data[1022:1024] = entry_data[fixup_array_offset + 4:fixup_array_offset + 6]
        entry_data = bytes(entry_data)
    log_sequence_number = as_signed_le(entry_data[8:16])
    sequence_number = as_signed_le(entry_data[16:18])
    number_of_links = as_signed_le(entry_data[18:20])
    first_attribute = as_signed_le(entry_data[20:22])
    attribute_offset = first_attribute
    while True:
        attribute_data = entry_data[attribute_offset:]
        attribute_type = as_signed_le(attribute_data[0:4])
        attribute_length = as_signed_le(attribute_data[4:8])
        attribute_non_resident = as_signed_le(attribute_data[8:9])
        if attribute_non_resident: #Non-resident
            print("Non Resident")
            #attribute_size = as_signed_le(attribute_data[40:48])
        else: #Resident
            print("Resident")
            #attribute_size = as_signed_le(attribute_data[16:20])
        if attribute_type == 0x10:
            standard_flag_value = as_signed_le(attribute_data[16 + 32: 16 + 36])
            standard_flag_data = get_flags(standard_flag_value)
        elif attribute_type == 0x30:
            print("$FILE_NAME")
        elif attribute_type == 0x80:
            print("$DATA")
        elif attribute_type == -1:
            break
        attribute_offset = attribute_offset + attribute_length
    result.append("MTF Entry Header Values:")
    result.append("Entry: " + str(address) + "\tSequence: " + str(sequence_number))
    result.append("$LogFile Sequence Number: " + str(log_sequence_number))
    result.append("Allocated File") #TODO implement
    result.append("Links: " + str(number_of_links))
    result.append("")
    result.append("$STANDARD_INFORMATION Attribute Values:")
    result.append("Flags: " + standard_flag_data)
    return result

def get_flags(value):
    flag_attributes = []
    if (0x0001 & value):
        flag_attributes.append("Read Only")
    if (0x0002 & value):
        flag_attributes.append("Hidden")
    if (0x0004 & value):
        flag_attributes.append("System")
    if (0x0020 & value):
        flag_attributes.append("Archive")
    if (0x0040 & value):
        flag_attributes.append("Device")
    if (0x0080 & value):
        flag_attributes.append("Normal")
    if (0x0100 & value):
        flag_attributes.append("Temporary")
    if (0x0200 & value):
        flag_attributes.append("Sparse file")
    if (0x0400 & value):
        flag_attributes.append("Reparse point")
    if (0x0800 & value):
        flag_attributes.append("Compressed")
    if (0x1000 & value):
        flag_attributes.append("Offline")
    if (0x2000 & value):
        flag_attributes.append("Content is not being indexed for faster searches") #This is the description provided in the book (Carrier)
    if (0x4000 & value):
        flag_attributes.append("Encrypted")
    return ", ".join(flag_attributes)

def into_localtime_string(windows_timestamp):
    """
    Convert a windows timestamp into istat-compatible output.

    Assumes your local host is in the EDT timezone.

    :param windows_timestamp: the struct.decoded 8-byte windows timestamp
    :return: an istat-compatible string representation of this time in EDT
    """
    dt = datetime.datetime.fromtimestamp((windows_timestamp - 116444736000000000) / 10000000)
    hms = dt.strftime('%Y-%m-%d %H:%M:%S')
    fraction = windows_timestamp % 10000000
    return hms + '.' + str(fraction) + '00 (EDT)'


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Display details of a meta-data structure (i.e. inode).')
    parser.add_argument('-o', type=int, default=0, metavar='imgoffset',
                        help='The offset of the file system in the image (in sectors)')
    parser.add_argument('-b', type=int, default=512, metavar='dev_sector_size',
                        help='The size (in bytes) of the device sectors')
    parser.add_argument('image', help='Path to an NTFS raw (dd) image')
    parser.add_argument('address', type=int, help='Meta-data number to display stats on')
    args = parser.parse_args()
    with open(args.image, 'rb') as f:
        result = istat_ntfs(f, args.address, args.b, args.o)
        for line in result:
            print(line.strip())
