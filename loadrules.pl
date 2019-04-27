#!/usr/bin/perl
# Author: Mark Vevers
# Version: 0.0.1a
# --------------------------------------------------------------------------
# Copyright (C) 2002 Mark Vevers <mark@vevers.net>
# Additional contributions by Michael Boman <michael.boman@securecirt.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# --------------------------------------------------------------------------
# Syntax loadrules.pl <Rule Directory>
# --------------------------------------------------------------------------
# Database configuration
$dbname="rman";
$dbuser="rman";
$dbpass="P\@ssw0rd1";


# --------------------------------------------------------------------------
use DBI;

$ruledir=$ARGV[0];

opendir RDIR, $ruledir || die ("Can't open rules dir");
$dbh = DBI->connect("DBI:mysql:".$dbname,$dbuser,$dbpass);

while($dirent=readdir RDIR) {
  R_FILES: {
    $dirent =~ /^(\S+)\.rules$/ && do {
      &loadrules($ruledir,$1,$dbh);
      
      last R_FILES;
    };
    &loadvars($ruledir,"snort.conf",$dbh);
    &loadpreprocessors($ruledir,"snort.conf",$dbh);
  }
}

closedir RDIR;
$result=$dbh->disconnect;
exit(0);


sub loadrules {
my $dir=$_[0];
my $ruleset=$_[1];
my $dbh=$_[2];
my $file=$dir.'/'.$ruleset.".rules";

  if (-e $file) {

    print "Ruleset: $ruleset\n";
    open RULES, $file || die ("Couldn't open ruleset $ruleset");
    $rgid=&getrulesetid($ruleset,$dbh);
    while (<RULES>) {
      R_RULES: {
        /^(drop|alert|log|pass|activate|dynamic)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+(\S+?)\s+\((.*)\)$/ && do {
          ($action, $proto, $s_ip, $s_port, $dir, $d_ip, $d_port, $options) = ($1, $2, $3, $4, $5, $6, $7, $8); 
          $rule=$_;
          
          $options =~ /msg:\s*\"(.*?)\"/;
          $rname = $1;     
          
          $options =~ /sid:\s*(\d+?)\s*;/;
          $rid = $1;
             
          $options =~ /rev:\s*(\d+?)\s*;/;
          $rev = $1;
 
          $sql1 = $dbh->prepare("SELECT rev FROM rman_rules WHERE rid = ?");
          $sql1->execute($rid);

          if ($sql1->rows == 0) {
            $sql2 = $dbh->prepare("INSERT INTO rman_rules (rid,rev,name,active,created,action,proto,s_ip,s_port,dir,d_ip,d_port,options) VALUES (?, ?, ?, 'Y', NULL,?,?,?,?,?,?,?,?)");
            $sql2->execute($rid, $rev, $rname,$action, $proto, $s_ip, $s_port, $dir, $d_ip, $d_port, $options);
            $sql2->finish;
	    $sql2 =$dbh->prepare("INSERT INTO rman_rrgid (rid,rgid) VALUES (?, ?)");
            $sql2->execute($rid,$rgid);
            $sql2->finish;
            &Rule_UpdateTimeStamp($dbh, $rid);
            $new="new";
            print "Rule $rid: $new, $rname\n";
          }      
          else {
            ($oldrev)=$sql1->fetchrow_array;
            if ($oldrev < $rev) {
              $new="Updated";
              $sql2 = $dbh->prepare("UPDATE rman_rules SET rev=?, name=?, action=?, proto=?, s_ip=?, s_port=?, dir=?, d_ip=?, d_port=?, options=? WHERE rid=?");
              $sql2->execute($rev, $rname, $action, $proto, $s_ip, $s_port, $dir, $d_ip, $d_port, $options, $rid);
              $sql2->finish;
              &Rule_UpdateTimeStamp($dbh, $rid);
              print "Rule $rid: $new, $rname\n";
            }
            else {
              $new="existing";
            }
          }
          $sql1->finish;


          last R_RULES;
        };
      }
    }
  }
  close RULES; 
}

sub getrulesetid {
  my $rset=$_[0];
  my $dbh=$_[1];
  my $rgid=0;

  $sql1 = $dbh->prepare("SELECT rgid FROM rman_rgroup WHERE name = ?");
  $sql1->execute($rset);
  
  if ($sql1->rows == 0) {
     $sql2=$dbh->prepare("INSERT INTO rman_rgroup (name,description) VALUES (?,?)");
     $sql2->execute($rset,$rset);
     $rgid=$sql2->{'mysql_insertid'};
     $sql2->finish;
  }
  else {
    ($rgid)=$sql1->fetchrow_array;
  }

  $sql1->finish;
  return($rgid);
}

sub Rule_UpdateTimeStamp {
  my $dbh=$_[0];
  my $rid=$_[1];
  my $sensor;

  $sql=$dbh->prepare("SELECT sid FROM rman_senrgrp, rman_rrgid, rman_rules WHERE rman_senrgrp.rgid=rman_rrgid.rgid AND rman_rules.active='Y' AND  rman_rrgid.rid = ? GROUP BY sid");
  $sql->execute($rid);

  if ($sql->rows != 0) {
    $sql1=$dbh->prepare("UPDATE rman_sensor SET updated = NULL WHERE sid = ?");
    while(($sensor)=$sql->fetchrow_array) {
      $sql1->execute($sensor);
    }
    $sql1->finish;
  }
  $sql->finish;
}


sub loadvars {
my $dir=$_[0];
my $ruleset=$_[1];
my $dbh=$_[2];
my $file=$dir.'/'.$ruleset;

  if (-e $file) {

    print "Configuration file: $ruleset\n";
    open RULES, $file || die ("Couldn't open configuration file $ruleset");
    while (<RULES>) {
      R_RULES: {
        /^var\s+(\S+?)\s+(.*)$/ && do {
          ($name, $value) = ($1, $2); 
          
	  #print "Name : $name\n";
	  #print "Value: $value\n";

          # Check if the variable is already known or not
          #print "DEBUG: SELECT vid FROM rman_vars WHERE vname = \"$name\"\n";
          $sql1 = $dbh->prepare("SELECT vid FROM rman_vars WHERE vname = \"$name\"");
          $sql1->execute();

          if ($sql1->rows == 0) {
            # First time we see this variable

            # Create the variable in the database
            #print "DEBUG: INSERT INTO rman_vars (vname) VALUES (\"$name\")\n";
            $sql2 = $dbh->prepare("INSERT INTO rman_vars (vname) VALUES (\"$name\")");
            $sql2->execute();
            $sql2->finish;

            # We need to figure out what ID number the variable got
            #print "DEBUG: SELECT vid FROM rman_vars WHERE vname = \"$name\"\n";
            $sql2 = $dbh->prepare("SELECT vid FROM rman_vars WHERE vname = \"$name\"");
            $sql2->execute();
            @array = $sql2->fetchrow_array;
            $vid = $array[0];
            $sql2->finish;

            if ( !$vid ) {
              print "\n\$vid == \"$vid\"\n\n";
              die ("\$vid is empty");
            }

            # Now insert the default value of the new variable
            #print "DEBUG: INSERT INTO rman_varvals (vid, sid, value, updated) VALUES (\"$vid\", \"0\", \"$value\", now())\n";
	    $sql2 =$dbh->prepare("INSERT INTO rman_varvals (vid, sid, value, updated) VALUES (\"$vid\", \"0\", \"$value\", now())");
            $sql2->execute();
            $sql2->finish;

            # Print status
            $new="new";
            print "var $name $value # $new\n";
          }      
          else {
            # We already have this variable

            # First we need to know what ID the variable has
            @array = $sql1->fetchrow_array;
            $vid = $array[0];

            if ( !$vid ) {
              print "\n\$vid == \"$vid\"\n\n";
              die ("\$vid is empty");
            }

	    # Commented out until we add a command line switch to allow control over whether default
	    # vars get updated if they already exist.
            # Update the default value for the variable
	    #print "DEBUG: UPDATE rman_varvals SET value = \"$value\" WHERE vid=\"$vid\"\n";
	    #$sql2 = $dbh->prepare("UPDATE rman_varvals SET value = \"$value\" WHERE vid=\"$vid\"");
	    #$sql2->execute();
	    #$sql2->finish;

            # Print status
            $new="Updated";
            print "var $name $value # $new\n";
          }
          $sql1->finish;

          last R_RULES;
        };
      }
    }
  }
  close RULES; 
}

sub loadpreprocessors {
my $dir=$_[0];
my $ruleset=$_[1];
my $dbh=$_[2];
my $file=$dir.'/'.$ruleset;

  if (-e $file) {

    print "Configuration file: $ruleset\n";
    open RULES, $file || die ("Couldn't open configuration file $ruleset");
    while (<RULES>) {
      R_RULES: {
        /^preprocessor\s+(\S+?)\s+(.*)$/ && do {
          ($name, $options) = ($1, $2); 

          $name =~ s/:$//;
          
	  #print "Name : $name\n";
	  #print "Options: $options\n";

          # Check if the variable is already known or not
          #print "DEBUG: SELECT pid FROM rman_preprocessors WHERE pname = \"$name\"\n";
          $sql1 = $dbh->prepare("SELECT pid FROM rman_preprocessors WHERE pname = \"$name\"");
          $sql1->execute();

          if ($sql1->rows == 0) {
            # First time we see this variable

            # Create the variable in the database
            #print "DEBUG: INSERT INTO rman_preprocessors (pname) VALUES (\"$name\")\n";
            $sql2 = $dbh->prepare("INSERT INTO rman_preprocessors (pname) VALUES (\"$name\")");
            $sql2->execute();
            $sql2->finish;

            # We need to figure out what ID number the variable got
            #print "DEBUG: SELECT pid FROM rman_preprocessors WHERE pname = \"$name\"\n";
            $sql2 = $dbh->prepare("SELECT pid FROM rman_preprocessors WHERE pname = \"$name\"");
            $sql2->execute();
            @array = $sql2->fetchrow_array;
            $pid = $array[0];
            $sql2->finish;

            if ( !$pid ) {
              print "\n\$pid == \"$pid\"\n\n";
              die ("\$pid is empty");
            }

            # Now insert the default value of the new variable
            #print "DEBUG: INSERT INTO rman_preprocessorvals (pid, sid, options, updated) VALUES (\"$pid\", \"0\", \"$options\", now())\n";
	    $sql2 =$dbh->prepare("INSERT INTO rman_preprocessorvals (pid, sid, options, updated) VALUES (\"$pid\", \"0\", \"$options\", now())");
            $sql2->execute();
            $sql2->finish;

            # Print status
            $new="new";
            if( $options ) {
              print "preprocessor $name: $options # $new\n";
            } else {
              print "preprocessor $name # $new\n";
            }
          }      
          else {
            # We already have this variable

            # First we need to know what ID the variable has
            @array = $sql1->fetchrow_array;
            $pid = $array[0];

            if ( !$pid ) {
              print "\n\$pid == \"$pid\"\n\n";
              die ("\$pid is empty");
            }

            # Update the default value for the variable
            #print "DEBUG: UPDATE rman_preprocessorvals SET options = \"$options\" WHERE pid=\"$pid\"\n";
            $sql2 = $dbh->prepare("UPDATE rman_preprocessorvals SET options = \"$options\" WHERE pid=\"$pid\"");
            $sql2->execute();
            $sql2->finish;

            # Print status
            $new="Updated";
            if( $options ) {
              print "preprocessor $name: $options # $new\n";
            } else {
              print "preprocessor $name # $new\n";
            }
          }
          $sql1->finish;

          last R_RULES;
        };
      }
    }
  }
  close RULES; 
}
