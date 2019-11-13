#!/usr/bin/perl
# **** License ****
#
# Copyright (c) 2018-2019, AT&T Intellectual Property.
# All rights reserved.
#
# Copyright (c) 2017 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2007-2015 Vyatta, Inc.
# All Rights Reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# **** End License ****
#
use strict;
use warnings;
use lib '/opt/vyatta/share/perl5';
use Vyatta::Config;
use Template;
use Getopt::Long;
use Sys::Syslog qw(:standard :macros);

my $config = new Vyatta::Config;

# Initalize defaults
my $vars = {
    Script              => $0,
    Port                => ["22"],
    Subsystem           => [],
    ClientAliveInterval => 0,
};

my $keygen       = 1;
my $update       = 0;
my $update_file  = '/etc/ssh/sshd_config';
my $priv_sep_dir = '/run/sshd';

sub setup_options {
    my ( $opts, $config, $cli_path ) = @_;
    $opts->{PermitRootLogin} =
      $config->exists("${cli_path}service ssh allow-root") ? "yes" : "no";
    $opts->{UseDNS} =
      $config->exists("${cli_path}service ssh disable-host-validation")
      ? "no"
      : "yes";
    $opts->{PasswordAuthentication} =
      $config->exists("${cli_path}service ssh disable-password-authentication")
      ? "no"
      : "yes";
    $opts->{AllowTcpForwarding} =
      $config->exists("${cli_path}service ssh disable-tcp-forwarding")
      ? "no"
      : "yes";
    return;
}

sub setup_listen_addrs {
    my ( $opts, $config, $cli_path ) = @_;
    my @addrs = $config->returnValues("${cli_path}service ssh listen-address");
    $opts->{ListenAddress} = [@addrs];
    return;
}

sub setup_ports {
    my ( $opts, $config, $cli_path ) = @_;
    my @ports = $config->returnValues("${cli_path}service ssh port");
    if ( scalar(@ports) < 1 ) {
        return;
    }
    $opts->{Port} = [@ports];
    return;
}

sub setup_netconf {
    my ( $opts, $config, $cli_path ) = @_;
    if ( defined( $config->exists("${cli_path}service netconf") )
        && !defined( $config->exists("${cli_path}service netconf disable") ) )
    {
        $opts->{Subsystem} =
          [ @{ $opts->{Subsystem} }, "netconf /opt/vyatta/bin/netconfd" ];
    }
    return;
}

sub setup_timeout {
    my ( $opts, $config, $cli_path ) = @_;
    my $timeout = $config->returnValue("${cli_path}service ssh timeout");

    if ( !defined($timeout) ) {
        return;
    }
    $opts->{LoginGraceTime} = $timeout;
    return;
}

sub setup_client_alive_interval {
    my ( $opts, $config ) = @_;
    my $timeout = $config->returnValue("system login session-timeout");

    return if !defined($timeout);

    $timeout = int( $timeout / 3 );
    if ( $timeout < 30 ) {
        return;
    }
    if ( $timeout > 235 ) {
        $timeout = 235;
    }
    $opts->{ClientAliveInterval} = $timeout;
    return;
}

sub setup_max_auth_retries {
    my ( $opts, $config, $cli_path ) = @_;
    my $max_auth_retries =
      $config->returnValue("${cli_path}service ssh authentication-retries");

    if ( !defined($max_auth_retries) ) {
        return;
    }
    $opts->{MaxAuthTries} = $max_auth_retries;
    return;
}

sub setup_ciphers {
    my ( $opts, $config, $cli_path ) = @_;
    my $ciphers =
      `/usr/sbin/sshd -T -f /dev/null | grep cipher | cut -d ' ' -f 2`;
    chomp $ciphers;
    my @cfg_ciphers =
      $config->returnValues("${cli_path}service ssh permit cipher");
    if ( scalar @cfg_ciphers > 0 ) {
        $ciphers = $ciphers . ',' . join( ',', @cfg_ciphers );
    }
    $opts->{Ciphers} = "$ciphers";
}

sub setup_kexalgorithms {
    my ( $opts, $config, $cli_path ) = @_;
    my $algs =
      `/usr/sbin/sshd -T -f /dev/null | grep kexalgorithms | cut -d ' ' -f 2`;
    chomp $algs;
    my @splitalgs = split( ',', $algs );

    # Remove initial disallowed list
    my $dis1    = "diffie-hellman-group1-sha1";
    my $dis2    = "diffie-hellman-group14-sha1";
    my $dis3    = "diffie-hellman-group-exchange-sha1";
    my @new     = grep { !/($dis1|$dis2|$dis3)/ } @splitalgs;
    my $newalgs = join( ',', @new );

    # Readd any specifically permitted by config
    my @cfg_kexalgs = $config->returnValues(
        "${cli_path}service ssh permit key-exchange-algorithm");
    if ( scalar @cfg_kexalgs > 0 ) {
        $newalgs = $newalgs . ',' . join( ',', @cfg_kexalgs );
        syslog( 'warning',
            "SSH: Legacy Key Exchange Algorithms enabled: @cfg_kexalgs" );
    }

    $opts->{KexAlgorithms} = "$newalgs";
}

sub setup_server_key_bits {
    my ( $opts, $config, $cli_path ) = @_;
    my %key_lengths = (
        "80"  => [ "1024", "1024",  "256" ],
        "112" => [ "1024", "2048",  "256" ],
        "128" => [ "1024", "3072",  "256" ],
        "192" => [ "1024", "7680",  "384" ],
        "256" => [ "1024", "15360", "521" ],
    );
    my $key_strength =
      $config->returnValue("${cli_path}service ssh key-security-strength");

    if ( !defined($key_strength) ) {
        system("ssh-keygen -A &>/dev/null");
        return;
    }

    my ( $dsa_len, $rsa_len, $ecdsa_len ) =
      @{ $key_lengths{$key_strength} };

    system(
"ssh-keygen -q -N '' -t ecdsa -b $ecdsa_len -f /etc/ssh/ssh_host_ecdsa_key &>/dev/null"
    );

    my $fips = `cat /proc/cmdline | grep "fips=1"`;
    if ( $fips eq "" ) {
        system(
"ssh-keygen -q -N '' -t dsa -b $dsa_len -f /etc/ssh/ssh_host_dsa_key &>/dev/null"
        );
        system(
"ssh-keygen -q -N '' -t rsa -b $rsa_len -f /etc/ssh/ssh_host_rsa_key &>/dev/null"
        );
    }
    return;
}

# Allow or deny sshd running at reboot depending on it being configured or not.
# Not needed for VRFs, as sshd_config for these are removed when config deleted
sub setup_run_at_startup {
    my $config     = shift;
    my $norun_file = "/etc/ssh/sshd_not_to_be_run";

    if ( defined( $config->exists("service ssh") ) ) {
        unlink $norun_file;
    } else {
        open( my $fh, '>', $norun_file )
          or die "Could not open file '$norun_file' $!";
        close $fh;
    }
}

sub update_handler {
    my ( $opt_name, $opt_value ) = @_;
    $update = 1;
    if ( length $opt_value ) {
        $update_file = $opt_value;
    }
}

my ($cli_path);

GetOptions(
    "keygen!"    => \$keygen,
    "update:s"   => \&update_handler,
    'cli-path=s' => \$cli_path
);

if ( !defined($cli_path) ) {
    $cli_path = "";
} else {
    $cli_path = $cli_path . " ";
}

mkdir $priv_sep_dir unless -d $priv_sep_dir;

setup_ports( $vars, $config, $cli_path );
setup_listen_addrs( $vars, $config, $cli_path );
setup_options( $vars, $config, $cli_path );
setup_netconf( $vars, $config, $cli_path );
setup_timeout( $vars, $config, $cli_path );
setup_client_alive_interval( $vars, $config );
setup_max_auth_retries( $vars, $config, $cli_path );
setup_ciphers( $vars, $config, $cli_path );
setup_kexalgorithms( $vars, $config, $cli_path );
setup_server_key_bits( $vars, $config, $cli_path ) if $keygen;
setup_run_at_startup($config) if $cli_path eq "";

my $tt = new Template( PRE_CHOMP => 1 );
if ($update) {
    $tt->process( \*DATA, $vars, $update_file );
} else {
    $tt->process( \*DATA, $vars );
}

__END__
### /etc/ssh/sshd_config is autogenerated by [% Script %]
### Note: Manual changes to this file will be lost during
###       the next commit.
[% FOREACH p = Port %]
Port [% p %]
[% END %]
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime [% LoginGraceTime %]
ClientAliveInterval [% ClientAliveInterval %]
MaxAuthTries [% MaxAuthTries %]
PermitRootLogin [% PermitRootLogin %]
StrictModes yes
PubkeyAuthentication yes
IgnoreRhosts yes
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication [% PasswordAuthentication %]
X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
Ciphers [% Ciphers %]
KexAlgorithms [% KexAlgorithms %]
AllowTcpForwarding [% AllowTcpForwarding %]
Banner /etc/issue.ssh
Subsystem sftp /usr/lib/openssh/sftp-server
[% FOREACH s = Subsystem %]
Subsystem [% s %]
[% END %]
UsePAM yes
UseDNS [% UseDNS %]
[% FOREACH addr = ListenAddress %]
ListenAddress [% addr %]
[% END %]
