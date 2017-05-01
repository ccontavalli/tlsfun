`tlsfun.py` is a small python script to output some interesting details
about a TLS stream.

The idea is simple: some protocols, like HTTP/1.0 or HTTP/1.1 don't generally use pipelining.
So the client sends a request, waits for a reply, sends another request and so on.
Of course, once the TLS handshake has been completed.

`tlsfun` will read a .pcap file specified from the command line, reconstruct the TCP
streams detected, and for each stream, determine what the "requests" are, what the "responses"
are, and by using `scapy` TLS support, it will dump the content of the requests and responses,
highlighting the amount of transferred ciphertext.

This tool was used for the blog post you can read here:

    http://rabexc.org/posts/guessing-tls-pages


# Installation

1. Download the python file (git clone, or save from your browser)

2. Install scapy on your system:

       sudo apt-get install python-scapy

3. Capture some traffic with tcpdump:

       tcpdump -s0 -nei wlan0 -w test.pcap 

3. Analyze it:

       ./tlsfun.py --dump ./test.pcap

       ./tlsfun.py --summary ./test.pcap


# Understanding the output

An example output might look like this:

    (('192.168.1.100', 44486), ('10.45.170.1', 443)) - 0
      requests tcp:220 r:215 ct:0 responses tcp:3124 r:3109 ct:0
      requests tcp:342 r:327 ct:64 responses tcp:75 r:65 ct:64
      requests tcp:2533 r:2528 ct:2528 responses tcp:45939 r:45904 ct:45904
      requests tcp:2485 r:2480 ct:2480 responses tcp:34957 r:34912 ct:34912
      requests tcp:2693 r:2688 ct:2688 responses tcp:405 r:400 ct:400
      requests tcp:2549 r:2544 ct:2544 responses tcp:3941 r:3936 ct:3936
      requests tcp:2533 r:2528 ct:2528 responses tcp:757 r:752 ct:752
      requests tcp:2565 r:2560 ct:2560 responses tcp:1733 r:1728 ct:1728
      requests tcp:2549 r:2544 ct:2544 responses tcp:1845 r:1840 ct:1840
      requests tcp:2549 r:2544 ct:2544 responses tcp:1797 r:1792 ct:1792
      requests tcp:2565 r:2560 ct:2560 responses tcp:917 r:912 ct:912
    
Now:

 * The first line '(('192.168.1.100' ... ))' indicates the 5 tuple: source ip, port, dest ip dest port. The '0' at the
   end is the index of the first packet in the connection, if you wanted to look at it via `scapy`.

 * Each following line represents an exchange. For example, the first line tells you
   that the client sent 220 bytes of TCP data, or 215 bytes of TLS records to the server, to receive a response
     of 3124 TCP bytes, or 3109 TLS records, and 0 ciphertext. This was probably part of the initial handshake.

If you use the `--dump` option, the output is similar and pretty self explanatory. The only things to remember are:

  * [xxxx] is the index of each packet in the pcap file.
  * &gt; or &lt; indicate the direction of the echange.
  * lines starting with 'buffer' indicate how the TCP packets since the last 'buffer' line have been
    reassembled and interpreted by the TLS parser. 
  * for example, a line like this:

        buffer: 34957 - /SSL/TLSRecord|771[8240]/TLSCiphertext{8240}/TLSRecord|771[496]/TLSCiphertext{496}/TLSRecord|771[8240]/TLSCiphertext{8240}/TLSRecord|771[48] 

    means that the previous packets were assembled in a single buffer of 34957 bytes, which contained a valid SSL header, followed
    by a TLSRecord object, TLSCiphertext, TLSRecord, ... with the corresponding sizes in square or curly brackets.
    Those names are generally easy to understand by reading the TLS RFCs, and the documentation of the scapy tls code,
    scapy.layers.ssl_tls.

