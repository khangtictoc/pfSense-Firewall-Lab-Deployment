#!/usr/bin/perl -w
use strict;
use warnings;

# Forces a flush after every write or print on the STDOUT
select STDOUT;
$| = 1;

# Get the input line by line from the standard input.
# Each line contains an URL and some other information.
while (<>) {
    my @parts = split;
    my $url   = $parts[0];
    if ( $url =~ /example\.com/ ) {

        # URL Rewriting
        print "http://www.uit.edu.vn\n";
    }
    else {
        # No Rewriting.
        print "\n";
    }
}
