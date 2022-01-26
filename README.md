# Go_Concurrent_PortScanner

A project I began to begin familiarizing myself with Go and its concurrency capabilities, among other things. 

# High level information

As it stands, it takes an individual host and range of ports, determining which are open. It currentl attempts an unintelligent banner grab, merely dumping the first 1024 bytes of the response. Later on I may add the ability for it to throw a few protocol-specific connection attempts at each open port to gather additional information. Results currently output to a plaintext file formatted by the program itself. At some point in the future I will add the ability to output to JSON, XML, etc.


