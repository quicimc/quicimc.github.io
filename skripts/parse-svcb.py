import argparse
import sys
import zstandard as zstd
import io
import csv

import dns.rdata as rd
import dns.rdtypes.svcbbase as svcb

"""
The following skript uses dnspython 2.1.0 to parse the output of massdns.
Massdns does not parse SVCB or HTTPS records yet but can only print the raw data.
"""


priority = {}
stats = {}
alpn = {}


def parse_line(line, output):
    splitted = line.split(" ")
    if splitted[3] == "HTTPS" or splitted[3] == "SVCB":
        rdata = " ".join(splitted[4:]).rstrip('\n').encode()

        test = rdata.decode('unicode_escape').encode('latin-1')

        try:
            res = rd.from_wire(1, 65, test, 0, len(test))
        except:
            print(line.rstrip('\n'), file=sys.stderr)
            return
        #print(res)
        alpn_string = []
        addresses = []
        port = ""
        for x in sorted(res.params.keys()):
            key = svcb.key_to_text(x)
            val = res.params[x]
            if key not in stats.keys():
                stats[key] = 1
            else:
                stats[key] += 1
            if 'alpn' == key:
                for application in val.ids:
                    alpn_string += [application.decode("utf-8")]
                    if application not in alpn.keys():
                        alpn[application] = 1
                    else:
                        alpn[application] += 1

            if "ipv6hint" == key or "ipv4hint" == key:
                addresses += val.addresses

            if "port" == key:
                port = val.port

        for address in addresses:
            if ":" in address:
                output.writerow([splitted[0], address, port, "6", ",".join(alpn_string)])
            else:
                output.writerow([splitted[0], address, port, "4", ",".join(alpn_string)])

        if res.priority not in priority.keys():
            priority[res.priority] = 1
        else:
            priority[res.priority] += 1


def main():
    parser = argparse.ArgumentParser(description='Process some integers.')

    parser.add_argument("-i", "--input", dest="input", help="input", metavar="FILE")
    parser.add_argument("-o", "--output", dest="output", help="input", metavar="FILE")
    args = parser.parse_args()

    with open(args.output, 'w', newline='') as csvfile:
        quicwriter = csv.writer(csvfile, delimiter=',',
                                quotechar='"', quoting=csv.QUOTE_MINIMAL)
        quicwriter.writerow(["domain", "address", "port", "version", "alpn"])

        if args.input.endswith(".zst"):
            with open(args.input, 'rb') as fh:
                dctx = zstd.ZstdDecompressor()
                stream_reader = dctx.stream_reader(fh)
                text_stream = io.TextIOWrapper(stream_reader, encoding='utf-8')

                for line in text_stream:
                    parse_line(line, quicwriter)
        else:
            with open(args.input) as fp:
                for line in fp:
                    parse_line(line, quicwriter)

    print(stats, file=sys.stderr)
    print(alpn,file=sys.stderr)
    print(priority, file=sys.stderr)


if __name__ == "__main__":
    main()

