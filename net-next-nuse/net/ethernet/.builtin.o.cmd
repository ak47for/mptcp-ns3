cmd_net/ethernet/builtin.o := mkdir -p ./net/ethernet/; rm -f ./net/ethernet/builtin.o; if test -n "./net/ethernet/eth.o"; then for f in ./net/ethernet/eth.o; do ar Tcru net/ethernet/builtin.o $$f; done; else ar Tcru net/ethernet/builtin.o; fi
