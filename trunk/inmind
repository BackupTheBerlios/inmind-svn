#!/usr/bin/perl

use strict;
use warnings;
use Net::DNS;
use Net::DNS::Nameserver;
use Thread;

our %mhash;

my $udp_port=53;

# FIXME : Does not support AAAA,CNAME,SOA .

# answer everything as authorative or not
my $auth=0;

my $verbose;
my $next_is_nameserver;
my $next_is_interface;
my $next_is_udpport;
my @nameservers;
my @interface;


foreach my $command (@ARGV) {

    if ($next_is_nameserver) {
	push (@nameservers , $command);
	if ($verbose) {&verbose("$command added to nameservers\n")};
	$next_is_nameserver=0;
	next;
    }

    elsif ($next_is_interface) {
	push (@interface , $command);
	if ($verbose) {&verbose("$command added to interfaces\n")};
	$next_is_interface=0;
	next;
    }

    elsif ($next_is_udpport) {
	$udp_port=$command;
	if ($verbose) {&verbose("udp port is now $command\n")};
	$next_is_udpport=0;
	next;
    }

    elsif ($command =~ '-*help') {
	print "In-Mind Dns Caching server\n";
	print "-i specify local address to bind to.\n";
	print "-n add Nameserver to list of nameservers , /etc/resolv.conf will get used by default.\n";
	print "-p Listeting udp port.\n";
	print "-v to be little more verbose.\n";
	print "--help to see this message.\n";
	print "\nExample : this server will listen on 127.0.0.1 udp port 55 and use all of -n arguments as nameserver .";
	print "inmind -v -i 127.0.0.1 -p 55 -i 1.1.1.1 -n 4.4.4.4 -n 2.2.2.2 -n 3.3.3.3 .\n";
	print "In-Mind is high performance Dns cacher .\n";
	print "For additional information, see http:\/\/inmind.berlios.de\/\n";
	exit;
    } elsif ($command =~ '-*v') {
	$verbose=1;
	next;
    } elsif ($command =~ '-*n') {
	$next_is_nameserver=1;
	next;
    } elsif ($command =~ '-*i') {
	$next_is_interface=1;
	next;
    } elsif ($command =~ '-*p') {
	$next_is_udpport=1;
	next;
    }}
undef $next_is_nameserver;
undef $next_is_interface;
undef $next_is_udpport;


my $res = Net::DNS::Resolver->new(
				  nameservers => \@nameservers,
				  recurse     => 1,
				  debug       => 0,
				  );


my $ns = Net::DNS::Nameserver->new(
				   LocalAddr        => \@interface,
				   LocalPort    => $udp_port,
				   ReplyHandler => \&handler,
				   Verbose      => 0,
				   ) || die "couldn't create nameserver object : $!\n";

$ns->main_loop;




sub handler {

    my ($qname, $qclass, $qtype, $peerhost) = @_;
    my ($rcode, @ans, @auth, @add);

    if ($mhash{$qname}{$qtype}) {
	if ($verbose) {&verbose("*** $qname $qtype is Cached \n")};
	my ($ttl, $rdata) = (0, $mhash{$qname}{$qtype});
	push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
	$rcode = "NOERROR";
	return ($rcode, \@ans, \@auth, \@add, { aa => $auth });

    } else {
	if ($verbose) {&verbose ("$qname $qtype is Uncached\n")};

if ($qtype eq "A") {
    my $t = Thread->new(\&type_A_uncache, ($qname, $qtype));
    my @retval = split (":",$t->join);
    if ($retval[0] ne "NXDOMAIN") {
	$mhash{$retval[0]}{$qtype}=$retval[1];
    }}

if ($qtype eq "MX") {
 my $t = Thread->new(\&type_MX_uncache, ($qname, $qtype));
 my @retval = split (":",$t->join);
 if ($retval[0] ne "NXDOMAIN") {
     $mhash{$retval[0]}{$qtype}=$retval[1];
 }
}

if ($qtype eq "PTR") {
my $t = Thread->new(\&type_PTR_uncache, ($qname,$qtype));             
 my @retval = split (":",$t->join);
 if ($retval[0] ne "NXDOMAIN") {
     $mhash{$retval[0]}{$qtype}=$retval[1];
 }}

if ($mhash{$qname}{$qtype}) {
    my ($ttl, $rdata) = (0, $mhash{$qname}{$qtype});
    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
    $rcode = "NOERROR";
} else {
    $rcode = "NXDOMAIN";
}


return ($rcode, \@ans, \@auth, \@add, { aa => $auth });
}}



sub type_A_uncache {
    my ($qname, $qtype) = @_;
    my $query = $res->search($qname);
    if ($query) {
	foreach my $rr ($query->answer) {
	    next unless $rr->type eq "A";
	    my $ansval = $qname.":".$rr->address;
	    return ($ansval);
	}} else {
	    return ("NXDOMAIN");
	}
}


sub type_MX_uncache {
    my ($qname, $qtype) = @_;
    my @mx   = mx($res, $qname);

    if (@mx) {
        foreach my $rr (@mx) {
            my $pref = $rr->preference;
            my $exc = $rr->exchange;
            my $ansval = "$qname:$pref $exc";
	    return ($ansval);
	}} else {
	    return ("NXDOMAIN");
	}}



sub type_PTR_uncache {
    my ($qname, $qclass, $qtype, $peerhost) = @_;
    my ($rcode, @ans, @auth, @add);
    my $qname_ip=$qname;
    $qname_ip =~ s/.in-addr.arpa//;
    my @arr = split ( '\.' , $qname_ip , 4 );
    $qname_ip=(join '.' ,$arr[3],$arr[2],$arr[1],$arr[0]);
    my $query = $res->search($qname_ip);

    if ($query) {
	foreach my $rr ($query->answer) {
	    next unless $rr->type eq "PTR";
	    my $ansval= $qname.":".$rr->ptrdname;
	    return ($ansval);
	}}
    return ("NXDOMAIN");

}


sub verbose {
	print "### @_";
    }
