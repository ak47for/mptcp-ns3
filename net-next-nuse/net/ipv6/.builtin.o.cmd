cmd_net/ipv6/builtin.o := mkdir -p ./net/ipv6/; rm -f ./net/ipv6/builtin.o; if test -n "./net/ipv6/af_inet6.o ./net/ipv6/anycast.o ./net/ipv6/ip6_output.o ./net/ipv6/ip6_input.o ./net/ipv6/addrconf.o ./net/ipv6/addrlabel.o ./net/ipv6/route.o ./net/ipv6/ip6_fib.o ./net/ipv6/ipv6_sockglue.o ./net/ipv6/ndisc.o ./net/ipv6/udp.o ./net/ipv6/udplite.o ./net/ipv6/raw.o ./net/ipv6/icmp.o ./net/ipv6/mcast.o ./net/ipv6/reassembly.o ./net/ipv6/tcp_ipv6.o ./net/ipv6/ping.o ./net/ipv6/exthdrs.o ./net/ipv6/datagram.o ./net/ipv6/ip6_flowlabel.o ./net/ipv6/inet6_connection_sock.o ./net/ipv6/sysctl_net_ipv6.o ./net/ipv6/xfrm6_policy.o ./net/ipv6/xfrm6_state.o ./net/ipv6/xfrm6_input.o ./net/ipv6/xfrm6_output.o ./net/ipv6/xfrm6_protocol.o ./net/ipv6/netfilter.o ./net/ipv6/fib6_rules.o ./net/ipv6/proc.o ./net/ipv6/syncookies.o ./net/ipv6/ah6.o ./net/ipv6/esp6.o ./net/ipv6/ipcomp6.o ./net/ipv6/xfrm6_tunnel.o ./net/ipv6/tunnel6.o ./net/ipv6/xfrm6_mode_transport.o ./net/ipv6/xfrm6_mode_tunnel.o ./net/ipv6/xfrm6_mode_ro.o ./net/ipv6/xfrm6_mode_beet.o ./net/ipv6/mip6.o ./net/ipv6/netfilter/builtin.o ./net/ipv6/sit.o ./net/ipv6/ip6_tunnel.o ./net/ipv6/ip6_gre.o ./net/ipv6/addrconf_core.o ./net/ipv6/exthdrs_core.o ./net/ipv6/ip6_checksum.o ./net/ipv6/ip6_icmp.o ./net/ipv6/output_core.o ./net/ipv6/protocol.o ./net/ipv6/ip6_offload.o ./net/ipv6/tcpv6_offload.o ./net/ipv6/udp_offload.o ./net/ipv6/exthdrs_offload.o ./net/ipv6/inet6_hashtables.o ./net/ipv6/ip6_udp_tunnel.o"; then for f in ./net/ipv6/af_inet6.o ./net/ipv6/anycast.o ./net/ipv6/ip6_output.o ./net/ipv6/ip6_input.o ./net/ipv6/addrconf.o ./net/ipv6/addrlabel.o ./net/ipv6/route.o ./net/ipv6/ip6_fib.o ./net/ipv6/ipv6_sockglue.o ./net/ipv6/ndisc.o ./net/ipv6/udp.o ./net/ipv6/udplite.o ./net/ipv6/raw.o ./net/ipv6/icmp.o ./net/ipv6/mcast.o ./net/ipv6/reassembly.o ./net/ipv6/tcp_ipv6.o ./net/ipv6/ping.o ./net/ipv6/exthdrs.o ./net/ipv6/datagram.o ./net/ipv6/ip6_flowlabel.o ./net/ipv6/inet6_connection_sock.o ./net/ipv6/sysctl_net_ipv6.o ./net/ipv6/xfrm6_policy.o ./net/ipv6/xfrm6_state.o ./net/ipv6/xfrm6_input.o ./net/ipv6/xfrm6_output.o ./net/ipv6/xfrm6_protocol.o ./net/ipv6/netfilter.o ./net/ipv6/fib6_rules.o ./net/ipv6/proc.o ./net/ipv6/syncookies.o ./net/ipv6/ah6.o ./net/ipv6/esp6.o ./net/ipv6/ipcomp6.o ./net/ipv6/xfrm6_tunnel.o ./net/ipv6/tunnel6.o ./net/ipv6/xfrm6_mode_transport.o ./net/ipv6/xfrm6_mode_tunnel.o ./net/ipv6/xfrm6_mode_ro.o ./net/ipv6/xfrm6_mode_beet.o ./net/ipv6/mip6.o ./net/ipv6/netfilter/builtin.o ./net/ipv6/sit.o ./net/ipv6/ip6_tunnel.o ./net/ipv6/ip6_gre.o ./net/ipv6/addrconf_core.o ./net/ipv6/exthdrs_core.o ./net/ipv6/ip6_checksum.o ./net/ipv6/ip6_icmp.o ./net/ipv6/output_core.o ./net/ipv6/protocol.o ./net/ipv6/ip6_offload.o ./net/ipv6/tcpv6_offload.o ./net/ipv6/udp_offload.o ./net/ipv6/exthdrs_offload.o ./net/ipv6/inet6_hashtables.o ./net/ipv6/ip6_udp_tunnel.o; do ar Tcru net/ipv6/builtin.o $$f; done; else ar Tcru net/ipv6/builtin.o; fi
