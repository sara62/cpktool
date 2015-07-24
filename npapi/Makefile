
all: libcpkplugin.so

libcpkplugin.so: main.o PluginObject.o CPKPlugin.o
	gcc -shared -I./include/ main.o PluginObject.o CPKObject.o \
		/usr/local/lib/libcpktool.a /usr/local/lib/libcpk.a /usr/local/lib/libcrypto.a \
		-o libcpkplugin.so

main.o:
	gcc -c main.c -I./include/

PluginObject.o:
	gcc -c PluginObject.c -I./include/

CPKPlugin.o:
	gcc -c CPKObject.c -I./include/

clean:
	rm -f *.o *.so

install:
	cp libcpkplugin.so /usr/share/mozilla/plugins/

