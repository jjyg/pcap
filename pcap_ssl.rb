#!/usr/bin/ruby

require './pcap'

module Pcap
	class TCP < Proto
		def parse_payload(data)
			# XXX should tcpflow or something..
			case data.str[0, 1].unpack('C')[0]
			when 20..23; SSLs.from(data)
			else super(data)
			end
		end
	end

	class SSLs < Proto
		def interpret(data)
			@a = []
			while not data.eos?
				@a << SSL.from(data)
			end
		end
		def inspect; @a.map { |h| h.inspect }.join("\n") end
	end
	class SSL < Proto
		attr_accessor :type, :major, :minor, :pld
		def interpret(data)
			@type = data.readbyte
			@major = data.readbyte
			@minor = data.readbyte
			@pld = parse_payload(data.readsub(data.readshort))
		end

		def parse_payload(data)
			case @type
			when 22; SSLHandshake.from(data)
			else super(data)
			end
		end
		def ver
			case [@major, @minor]
			when [3, 0]; 'SSLv3'
			when [3, 1]; 'TLS1.0'
			when [3, 2]; 'TLS1.1'
			when [3, 3]; 'TLS1.2'
			end
		end
		def type_s
			{ 20 => 'ChangeCipherSpec', 21 => 'Alert', 22 => 'Handshake', 23 => 'Application' }[@type]
		end
		def inspect
			" <ssl type=#@type-#{type_s} vers=#@major.#@minor-#{ver}\n#{@pld.inspect}>"
		end
	end

	class SSLHandshake < Proto
		attr_accessor :type, :pld
		def interpret(data)
			len = data.readlong
			@type = len >> 24
			len &= 0xff_ffff
			@pld = parse_payload(data.readsub)
		end

		def type_s
			{ 0 => 'HelloRequest', 1 => 'ClientHello', 2 => 'ServerHello',
			 11 => 'Certificate', 12 => 'ServerKeyExchange', 13 => 'CertificateRequest',
			 14 => 'ServerHelloDone', 15 => 'CertificateVerify', 16 => 'ClientKeyExchange',
			 20 => 'Finished' }[@type]
		end

		def inspect
			"  <sslhandshake type=#@type-#{type_s} #{@pld.length.h}\n#{@pld.inspect}>"
		end
	end
end

if __FILE__ == $0
	Pcap.dump_cli
end
