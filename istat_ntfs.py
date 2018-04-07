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
    mft_data = data[mft_start:]
    mft_entry_size = as_signed_le(data[64:65])
    log_sequence_number = as_signed_le(mft_data[8:16])
    sequence_number = as_signed_le(mft_data[16:18])
    number_of_links = as_signed_le(mft_data[18:20])
    result.append("MTF Entry Header Values:")
    result.append("Entry: " + str(address) + "\tSequence: " + str(sequence_number))
    result.append("$LogFile Sequence Number: " + str(log_sequence_number))
    result.append("Allocated File") #TODO implement
    result.append("Links: " + str(number_of_links))
    result.append("")
    result.append("$STANDARD_INFORMATION Attribute Values:")
    result.append("Flags: ")
    print("===============================")
    for s in result:
        print(s)
    print("===============================")
    return result


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
