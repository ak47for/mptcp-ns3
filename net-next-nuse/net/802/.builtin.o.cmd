cmd_net/802/builtin.o := mkdir -p ./net/802/; rm -f ./net/802/builtin.o; if test -n ""; then for f in ; do ar Tcru net/802/builtin.o $$f; done; else ar Tcru net/802/builtin.o; fi
