#!/usr/bin/ruby

# a full ruby pcap file parser
# (c) Yoann Guillot 2009
# License : wtfplv2 (zoy.org)

class String ;  def h ; unpack('H*').first end end
class Integer ; def h ; '0x%x' % self end end 

module Pcap
	class Sbuf
		attr_accessor :pos, :str
		def initialize(str)
			@pos = 0
			@str = str
		end
		def read(len=-1)
			puts "short string!" if $VERBOSE and eos?
			# len < 0 -> read up to len (-1 = read all)
			len = @str.length + len + 1 - @pos if len < 0
			@pos += len
			@str[@pos-len, len].to_s
		end
		def readsub(len=-1)
			self.class.new(read(len))
		end
		def readbyte ;  read(1).unpack('C').first end
		def readshort ; read(2).unpack('n').first end
		def readlong ;  read(4).unpack('N').first end
		def eos? ; @pos >= @str.length end
	end

	class Capture
		def self.from(io)
			c = new
			c.from(io)
			c
		end

		attr_accessor :io, :endianness, :version, :tz, :filelen, :futureap, :linktype

		def from(io)
			@io = io
			@endianness = :little
			case signature = readlong
			when 0xa1b2c3d4
			when 0xd4c3b2a1: @endianness = :big
			else raise "invalid signature #{'%x' % signature}"
			end

			@version = [readshort, readshort]
			@tz = readlong
			@filelen = readlong
			@futureap = readlong
			@linktype = readlong
			@linktype = :eth if @linktype == 1
		end

		def readpacket
			Packet.read(self)
		end

		def readlong
			@io.read(4).unpack(@endianness == :big ? 'N' : 'V').first
		end
		def readshort
			@io.read(2).unpack(@endianness == :big ? 'n' : 'v').first
		end
		def read(len)
			@io.read(len)
		end
		def eof? ; @io.closed? or @io.eof?  end
	end

	class Packet
		attr_accessor :length, :time, :eth

		def self.read(cap)
			p = new
			p.read(cap)
			p
		end

		def read(cap)
			@time = cap.readlong
			@time += cap.readlong / 1_000_000.0
			@length = cap.readlong
			rawlen = cap.readlong
			@eth = Ethernet.from(Sbuf.new(cap.read(rawlen)))
		end
		def inspect
			"<pcap time=#@time-#{Time.at(@time).strftime('%d/%m/%Y %H:%M:%S') rescue nil} length=#@length\n#{@eth.inspect}>"
		end
	end

	class Proto
		def self.from(str)
			n = new
			n.interpret(str)
			n
		end
	end

	class Ethernet < Proto
		attr_accessor :src, :dst, :type, :ip
		def interpret(data)
			@src  = data.read(6)
			@dst  = data.read(6)
			@type = data.readshort
			@ip   = IP.from(data.readsub(-5))
			crc  = data.readlong
		end

		def inspect
			"<eth src=#{@src.h.scan(/../).join(':')} dst=#{@dst.h.scan(/../).join(':')} type=#{@type.h}\n#{@ip.inspect}>"
		end
	end

	class IP < Proto
		attr_accessor :vers, :id, :flag, :frag, :ttl, :proto, :src, :dst, :opts, :pld

		def interpret(data)
			b = data.readbyte
			@vers = b >> 4
			hdrlen = (b & 0xf) * 4
			tos = data.readbyte
			len = data.readshort
			@id = data.readshort
			@frag = data.readshort
			@flag = @frag >> 14
			@frag &= 0x3fff
			@ttl = data.readbyte
			@proto = data.readbyte
			hcksum = data.readshort
			@src = data.read(4)
			@dst = data.read(4)
			@opts = data.read(hdrlen-data.pos)
			data = data.readsub(len-data.pos)
			@pld = case @proto
			when 6: TCP.from(data)
			when 17: UDP.from(data)
			when 1: ICMP.from(data)
			else data.read
			end
		end

		def inspect
			"<ip src=#{@src.unpack('C*').join('.')} dst=#{@dst.unpack('C*').join('.')} id=#{@id.h} flag=#@flag proto=#@proto\n#{@pld.inspect}>"
		end
	end

	class TCP < Proto
		attr_accessor :sport, :dport, :seq, :ack, :flags, :wsz, :urgent, :opts, :pld

		def interpret(data)	
			@sport = data.readshort
			@dport = data.readshort
			@seq = data.readlong
			@ack = data.readlong
			doff = data.readbyte >> 4 << 2
			@flags = data.readbyte	# hi->lo: cwr ece urg ack psh rst syn fin
			@wsz = data.readshort
			cksum = data.readshort
			@urgent = data.readshort
			@opts = data.read(doff-data.pos)
			@pld = data.read
		end
		def flags_s
			# to_s(2) is not rjust(8)
			%w[cwr ece urg ack psh rst syn fin].reverse.zip(@flags.to_s(2).split(//).reverse).map { |f, b| f if b == '1' }.compact.join(',')
		end

		def inspect
			"<tcp sport=#@sport dport=#@dport seq=#{@seq.h} flag=#{@flags.h}-#{flags_s}\n#{@pld.inspect}>"
		end
	end

	class UDP < Proto
		attr_accessor :sport, :dport, :pld

		def interpret(data)	
			@sport = data.readshort
			@dport = data.readshort
			len = data.readshort
			cksum = data.readshort
			@pld = data.read(len-8)
		end

		def inspect
			"<udp sport=#@sport dport=#@dport\n#{@pld.inspect}>"
		end
	end

	class ICMP < Proto
		attr_accessor :type, :code, :id, :seq, :pld

		def interpret(data)
			@type = data.readbyte
			@code = data.readbyte
			cksum = data.readshort
			@id   = data.readshort
			@seq  = data.readshort
			@pld = data.read
		end

		def inspect
			"<icmp type=#@type code=#@code id=#@id seq=#@seq\n#{@pld.inspect}>"
		end
	end
end

if __FILE__ == $0
	abort 'usage: pcap.rb <pcapfile>' if ARGV.empty?
	p pc = Pcap::Capture.from(ARGF)
	p pc.readpacket until pc.eof?
end

__END__
http://www.mail-archive.com/winpcap-users@winpcap.polito.it/msg02243.html
> Well, the page at
>
>         http://analyzer.polito.it/docs/advanced_man/how_to/add_new_lff.htm
>
> gives libpcap format as an example, although there are a few errors:
>
>         1) "File Length" is actually nominally "Significant
> Figures", which
> would, in theory, be the accuracy of time stamps, but, in practice, it's
> always zero and gives no information;
>
>         2) "Future Applications" is actually "Snapshot Length",
> which is the
> maximum number of packet data in any of the records of the file - or a
> value greater than or equal to that maximum, and is often 65535 (some
> software might use it to allocate a buffer into which to copy the packet
> data);
>
> and also:
>
>         1) "Time Zone" is often 0, so it can't be relied on to contain the
> offset of the time zone, at the location of the capture, from UTC in
> seconds;
>
>         2) "Link Type" shouldn't use the values 11, 12, 13, or 14
> - there are
> other values that should be used for those purposes - and has some other
> values that are available.

http://analyzer.polito.it/docs/advanced_man/how_to/add_new_lff.htm
At the beginning of the file there is an header. Here it is its format:
Magic Number
Major Version 	Minor Version
Time Zone
File Length
Future Applications
Link Type

Each file starts with a magic number. This number contains the hexadecimal sequence: 0xa1b2c3d4. It is used to understand if the file was generated by a little endian architecture or by a big endian architecture. In the little endian case the bytes sequence is: 0xa1, 0xb2, 0xc3, 0xd4; in the big endian case: 0xd4, 0xc3, 0xb2, 0xa.
Then there are two integers on two byte which represent the major and the minor version of the format.
An integer on 4 bytes which contains the time zone in relation with Greenwich.
An integer on 4 bytes which contains the file length.
An integer on 4 bytes reserved for future applications.
An integer on 4 bytes describes the link (Ethernet, ...). Complete mapping can be found into bpf.h file, into the WinPcap source pack. Here it it a table which show the values which this number can have and their meanings: 

Value                        	Description
0 	no link-layer encapsulation
1 	Ethernet (10Mb)
2 	Experimental Ethernet (3Mb)
3 	Amateur Radio AX.25
4 	Proteon ProNET Token Ring
5 	Chaos
6 	IEEE 802 Networks
7 	ARCNET
8 	Serial Line IP
9 	Point-to-point Protocol
10 	FDDI
11 	LLC/SNAP encapsulated ATM
12 	Raw IP
13 	BSD/OS Serial Line IP
14 	BSD/OS Point-to-point Protocol

Then there are the packets; each packet has an header which contains the following information:
Packet Length
The packet part length contained in the file
Seconds from the capture beginning
Micro seconds from the capture beginning

An integer on 4 bytes for the packet length.
An integer on 4 bytes for the length of the packet part contained in the file. In fact can happen that the capture file does not contain the whole packet.
An integer on 4 bytes keeps the seconds number passed since the capture beginning until when the packet was captured.
An integer on 4 bytes keeps the microseconds number passed since the capture beginning until when the packet was captured. 

// jj: from net2pcap.c, timestamp comes first
network packet formats from wikipedia
