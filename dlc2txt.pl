#!/usr/bin/perl -w
# Created @ 01.04.2009 by TheFox@fox21.at
# Version: 1.1.1
# Copyright (c) 2009, 2010 TheFox

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Description:
# Decrypt .dlc files. Containers sucks. Really!

# THX to
# eddy14 (http://41yd.de/blog/2008/11/15/dlc-geknackt/)


use strict;
use FindBin;
use CGI;
use CGI::Carp qw(fatalsToBrowser);
use LWP::Simple;
use LWP::UserAgent;
use HTTP::Request;
use HTTP::Request::Common qw(GET POST);
use HTTP::Response;
use MIME::Base64;
use Crypt::Rijndael;
use File::Basename;

$| = 1;


my $DEBUG = 0; # TODO
my $VERSION = '1.1.1';

my $KEYFILE = ''; # TODO
#my $KEYFILE = './dlc2txt.keys'; # Optional.
my $KEYA = '';
my $KEYB = '';
my $PROGNAME = ''; # program identification like 'jdtc5', 'rsdc', 'load', ...

my $BINDIP = '';
my $USERAGENT = 'User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.10) Gecko/2009042523 Ubuntu/9.04 (jaunty) Firefox/3.0.10';
#my $JLINK = 'http://service.jdownloader.org/dlcrypt/service.php?destType={$PROGNAME}&srcType=dlc&data=';
my $JLINK = 'http://service.jdownloader.org/dlcrypt/service.php';
my $TAILLEN = 88;
my $IV = pack 'H*', '00000000000000000000000000000000';

sub main{
	
	chdir $FindBin::Bin;
	
	my $self = basename $0;
	
	my $ua = LWP::UserAgent->new('max_redirect' => 5);
	my $req;
	my $retval;
	my $content;
	my $cgi = new CGI();
	my %input = ();
	
	$ua->agent($USERAGENT);
	
	if(!defined @ARGV){
		for my $key ($cgi->param()){
			$input{$key} = $cgi->param($key);
		}
	}
	else{
		for my $row (@ARGV){
			if(defined $row){
				my @s = split '=', $row, 2;
				$input{$s[0]} = $s[1] if @s > 1;
			}
		}
	}
	
	# optional
	if(-e $KEYFILE){
		open KEYS, '<', $KEYFILE;
		my $keys = join '', <KEYS>;
		close KEYS;
		$keys = decode_base64($keys);
		if($keys =~ /^([^:]+)::([^:]+)::([^:]+)$/si){
			($PROGNAME, $KEYA, $KEYB) = ($1, $2, $3);
		}
	}
	
	$JLINK =~ s/\{\$PROGNAME\}\E/$PROGNAME/sig;
	
	
	$input{'a'} = 'default' unless defined $input{'a'};
	$input{'sa'} = 'default' unless defined $input{'sa'};
	
	my $action = $input{'a'} ;
	my $subaction = $input{'sa'};
	
	if($action eq 'default'){
		print "Content-type: text/html\n\n";
		my $error = '';
		if($KEYA eq '' || $KEYB eq '' || $PROGNAME eq ''){
			$error = '<font color="#ff0000"><b>ERROR: You need to set $KEYA and $KEYB and $PROGNAME!!!</b></font><br />';
		}
		if($DEBUG){
			print "DEBUG: key: $PROGNAME, $KEYA, $KEYB<br />";
		}
		print qq(
			<html>
				<head>
					<title>dlc Decrypter v. $VERSION from fox21.at</title>
				</head>
				<body>
					$error
					<form action="" method="post">
						<input type="hidden" name="a" value="exec" />
						Copy and paste the content of the .dlc file into this text area<br />
						<textarea name="content" rows="10" cols="60"></textarea><br /><br />
						<input type="submit" value="Get" />
					</form>
				</body>
			</html>
		);
	}
	elsif($action eq 'exec'){
		print "Content-type: text/html\n\n";
		
		my $out = '';
		my $dlc = $input{'content'};
		
		my $error = '';
		if($KEYA eq '' || $KEYB eq '' || $PROGNAME eq ''){
			$error = '<font color="#ff0000"><b>ERROR: You need to set $KEYA and $KEYB and $PROGNAME!!!</b></font><br />';
		}
		if($dlc eq ''){
			$error = '<font color="#ff0000"><b>ERROR: No .dlc content.</b></font><br />';
		}
		if($error ne ''){
			print $error;
			exit 0;
		}
		
		
		$dlc =~ s/[\r\n]+//s;
		if($DEBUG){
			print "DEBUG: dlc len: ".length($dlc)."<br />";
		}
		
		my $tail = substr $dlc, length($dlc) - $TAILLEN;
		$dlc = substr $dlc, 0, length($dlc) - length($tail);
		$dlc = decode_base64($dlc);
		
		my $response = '';
		#$req = GET($JLINK.$tail);
		$req = POST(
			$JLINK,
			'Content-type' => 'application/x-www-form-urlencoded',
			'Accept' => 'text/plain,text/html',
			'Accept-Encoding' => '', # Anti Gzip.
			'Content' => [
				'destType' => $PROGNAME,
				'srcType' => 'dlc',
				'data' => $tail,
			],
		);
		if($DEBUG){
			print "DEBUG: request: <pre>".$req->as_string()."</pre><br />";
		}
		setLocalAddr($BINDIP);
		$retval = $ua->request($req);
		if($DEBUG){ print "DEBUG: response: <pre>".$retval->as_string()."</pre><br />"; }
		$response = $retval->content();
		
		my $responseKey = '';
		my $responseKeyDeb64 = ''; # Response key base64 decrypted.
		my $responseKeyError = 0;
		
		if($response =~ /<rc>(.*)<.rc>/si){
			$responseKey = $1;
			if($DEBUG){
				print "DEBUG: responseKey: $responseKey<br />";
				print "DEBUG: responseKey hex: ".(unpack 'H*', $responseKey)."<br />";
			}
		}
		else{
			$responseKeyError = 1;
		}
		
		# According to jdownloader decompiled code. Haha MF!
		if($responseKey eq '2YVhzRFdjR2dDQy9JL25aVXFjQ1RPZ'){
			$responseKeyError = 1;
		}
		if($responseKeyError == 1){
			print '<font color="#ff0000"><b>ERROR: You recently opened to many DLCs. Please wait a few minutes.</b></font><br />';
		}
		
		$responseKeyDeb64 = decode_base64($responseKey);
		if($DEBUG){
			print "DEBUG: responseKeyDeb64: ".(unpack 'H*', $responseKeyDeb64)."<br />";
		}
		
		
		my $cipher = Crypt::Rijndael->new($KEYA, Crypt::Rijndael::MODE_ECB());
		$cipher->set_iv($IV);
		my $responseKeyDeb64Decr = $cipher->decrypt($responseKeyDeb64);
		my $newkey = xorcrypt($responseKeyDeb64Decr, $KEYB);
		my $newdlc = $newkey.$dlc;
		
		if($DEBUG){
			print "DEBUG: responseKeyDeb64Decr: ".(unpack 'H*', $responseKeyDeb64Decr)."<br />";
			print "DEBUG: newkey: ".(unpack 'H*', $newkey)."<br />";
		}
		
		$cipher = Crypt::Rijndael->new($newkey, Crypt::Rijndael::MODE_ECB());
		$cipher->set_iv($IV);
		
		my $xml = '';
		while(length $dlc > 0){
			my $dlclen = length $dlc;
			my $rest = $dlclen >= 16 ? 16 : $dlclen;
			my $cutold = substr $dlc, 0, $rest;
			my $cutnew = substr $newdlc, 0, $rest;
			$dlc = substr $dlc, $rest;
			$newdlc = substr $newdlc, $rest;
			$cutold = $cipher->decrypt($cutold);
			$cutold = xorcrypt($cutold, $cutnew);
			$xml .= $cutold;
		}
		
		if($DEBUG){
			print "DEBUG: xml: <pre>$xml</pre><br />";
		}
		$xml = decode_base64($xml);
		if($DEBUG){
			print "DEBUG: xml decode_base64: <pre>$xml</pre><br />";
		}
		
		my @strs = ();
		while($xml =~ />([a-z0-9\+\/_=-]+)</sig){
			push @strs, $1;
		}
		while($xml =~ /"([a-z0-9\+\/_=-]+)"/sig){
			push @strs, $1;
		}
		
		for my $search (@strs){
			while(length($search) % 4){
				$search .= '=';
			}
			my $db64 = decode_base64($search);
			$xml =~ s/\Q$search\E/$db64/s;
		}
		
		if($xml =~ /<content>(.*)<.content>/sig){
			if($DEBUG){
				print "DEBUG: xml ok<br />";
			}
			my $xmlContent = $1;
			for my $xmlUrl (split '<url>', $xmlContent){
				if($xmlUrl =~ /^(.*)<.url>/si){
					$out .= "$1\n";
				}
			}
		}
		
		print qq(
			<html>
				<head>
					<title>dlc Decrypter v. $VERSION from fox21.at</title>
				</head>
				<body>
					<textarea rows="20" cols="80">$out</textarea><br />
					<a href="$self">Next file</a>
				</body>
			</html>
		);
	}
	
}

sub setLocalAddr{
	my($ip) = @_;
	$ip = '' unless defined $ip;
	if($ip ne ''){
		push(@LWP::Protocol::http::EXTRA_SOCK_OPTS, 'LocalAddr' => $ip);
		push(@LWP::Protocol::http::EXTRA_SOCK_OPTS, 'LocalPort' => (int rand 20000) + 20000);
	}
}

sub xorcrypt{
	my($data, $key) = @_;
	my $encrypt = '';
	my $kc = 0;
	my $kl = length $key;
	my $dl = length $data;
	for(my $i = 0; $i < $dl; $i++){
		my $c = substr $data, $i, 1;
		$kc = 0 if $kc > $kl - 1;
		my $k = substr $key, $kc, 1;
		$kc++;
		$encrypt .= chr(ord($c) ^ ord($k));
		#print "$i: >$c<\n"; sleep 1;
	}
	$encrypt;
}

main();

# EOF
