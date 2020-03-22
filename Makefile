
all: server_obj client_obj

server_obj:
	cd server;$(MAKE) -f Makefile 
client_obj:
	cd client;$(MAKE) -f Makefile 

clean:
	cd server;$(MAKE) -f Makefile clean
	cd client;$(MAKE) -f Makefile clean

