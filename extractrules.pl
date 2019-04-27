#!/usr/bin/perl
# Author: Mark Vevers
# Version: 0.0.1a
# --------------------------------------------------------------------------
# Copyright (C) 2002 Mark Vevers <mark@vevers.net>
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


use DBI;
use Cwd 'chdir';

#---------------------------------------------------------------------------
# Additional script configs you might want to edit
$config="db.config";
$time="db.timestamp";
$snortpid="/var/run/snort_";
$ruledir="/usr/local/snort/rules";
$snortbin="/usr/local/bin/snort";
$snortargs="-oz -k noip";   # script adds interface

# --------------------------------------------------------------------------
# Change dir to ruledir
chdir $ruledir;

# --------------------------------------------------------------------------
# Read config

open (CONFIG, "$config") || die "Can't open output $file\n";

while (<CONFIG>) {
  chop;
  R_CONFIG: {
    /^## (\S+):\s*(\S+)\s*$/ && do {
    $config{$1}=$2;
    last R_CONFIG;
    };
  }
}
close CONFIG;

#-------------------------------------------------------
# update snort args and pid location
$snortargs .= " -i ".$config{"senintf"};
$snortpid .= $config{"senintf"}.".pid";

#--------------------------------------------------------
# Connect to DB and check sensor registration

$dbistring="DBI:mysql:".$config{"dbname"}.":".$config{"dbserv"};
$dbh = DBI->connect($dbistring,$config{"dbuser"},$config{"dbpasswd"});

$sql = $dbh->prepare("SELECT sid FROM sensor WHERE hostname = ? AND interface = ?");
$sql->execute($config{"senname"},$config{"senintf"});

if (!(($sid)=$sql->fetchrow_array)) {
  print "Sensor does not exist in db - exiting\n";
  $sql->finish;
  exit(1);
}
$sql->finish;


# --------------------------------------------------------------
# Check process health 

$snort=&getsnortpid($snortpid);

if (&updated($sid,$dbh,$time)) {
  &outputrules($sid, $ruledir, $dbh);
  &outputvars($sid,$ruledir,$dbh);
  &outputpreprocessors($sid,$ruledir,$dbh);
  if(&testnewconfig($sid,$ruledir,$dbh,$snortbin,$snortargs)) {
    &logit("New Ruleset loaded");
    # Restart if running
    if ($snort!=0) {
      &logit("Sending snort a restart");
      $kill=`kill -1 $snort`;
      # Now check snort is still running
      sleep(1);
      $snort=&getsnortpid($snortpid);
    }
  }
  else {
    &logit("New Ruleset failed sanity check! See test.log for results");
  }  
}

# If snort has failed try a restart
if ($snort==0) {
  &logit("Snort not running - restarting");
  $cmd=$snortbin." -c ".$ruledir."/snort.conf ".$snortargs." -D";
  $startit=`$cmd`;
  sleep(1);
  $snort=&getsnortpid($snortpid);
  if ($snort!=0) {
    &logit("Restart Succeeded");
  }
  else {
    &logit("Restart Failed");
  }
} 

$result=$dbh->disconnect;
exit(0);

#------------------------------------------
#If snort is running return pid.
# return 0 if no process found

sub getsnortpid {
  my $snortpid=$_[0];
  my $snort, $running=0;

  # Check file exists, if it does check if process it gives is running
  if ( -e $snortpid) {
    $snort=`cat $snortpid`;
    $running=`ps ax | grep -v grep | grep -c $snort`;
  }
  
  if ($running>=1) {
    return($snort);
  }
  return(0);
}

sub testnewconfig {

my $sid=$_[0];
my $rdir=$_[1];
my $dbh=$_[2];
my $sbin=$_[3];
my $args=$_[4];
my @cmd;
my $success=0;
my $statusflag=0;

  # Check to see if sensor has an entry in the status table.
  $sql = $dbh->prepare("SELECT statusflag FROM rman_sensor_status WHERE sid=?");
  $sql->execute($sid);

  # Nope - Create it.
  if ($sql->rows == 0) {
    $sql_new = $dbh->prepare("INSERT INTO rman_sensor_status (sid,statusflag) VALUES (?,0)");
    if (!$sql_new->execute($sid)) {
      &logit("DB Error - cannot create status entry : ".$sql_new->errstr);
      die "Error:".$sql_new->errstr . "\n";
    }
    $sql_new->finish;
  }
  
  # OH DEAR! ... we've got more than one entry .... err ... die!
  if ($sql->rows > 1) {
    &logit("DB Error - More than one sensor entry in rman_sensor_status");
    die "DB Error - More than one sensor entry in rman_sensor_status\n";
  }
  
  $statusflag=$sql->fetchrow_array;
  $sql->finish;
  
  # OK, now it's time to test the new ruleset.  First we have to rename the vars as they are included from the conf file ...
  if (rename ($rdir."/db.vars", $rdir."/db.vars.old")) {
    if (rename ($rdir."/db.vars.new", $rdir."/db.vars")) { 
      $success=1;
    }
    else {
      rename ($rdir."/db.vars.old", $rdir."/db.vars");
    }	     
  }

  if ($success==0) {
    &logit("Failed to rename vars to vars.old");
    die("Failed to rename vars to allow test");
  }
  
  $success=0;
  
  # We have to rename the preoprocessors as they are included from the conf file ...

  if (rename ($rdir."/db.preprocessors", $rdir."/db.preprocessors.old")) {
    if (rename ($rdir."/db.preprocessors.new", $rdir."/db.preprocessors")) { 
      $success=1;
    }
    else {
      rename ($rdir."/db.preprocessors.old", $rdir."/db.preprocessors");
    }	     
  }

  if ($success==0) {
    &logit("Failed to rename vars to preprocessors.old");
    die("Failed to rename vars to allow test");
  }
  
  $success=0;

  if (rename($rdir."/db.rules", $rdir."/db.rules.old")) {
    if (rename($rdir."/db.rules.new", $rdir."/db.rules")) {
      $success=1;
    }
  }
  
  if ($success==0) {
    &logit("Failed to rename rules to rules.old");
    rename ($rdir."/db.vars", $rdir."/db.vars.new");
    rename ($rdir."/db.vars.old", $rdir."/db.vars");
    die("Failed to rename rules to allow test");
  }
  
  
  $cmd=$sbin." -c " .$rdir."/snort.conf " .$args. " -T > ".$rdir."/rulestest.log 2>&1";  
  
  $success=system($cmd);
  
  print $success>>8;
  $log=`cat $rdir/rulestest.log`;
 
  $sqllog=$dbh->prepare("UPDATE rman_sensor_status SET statusflag=?, lastlog=?, lastupdate = NULL WHERE sid=?");
  
  if($success==0) {
    $statusflag=$statusflag | 0x00000001; 
    $sqllog->execute($statusflag,$log,$sid);
    $sqllog->finish;
    return(1);
  }
  else {
    rename ($rdir."/db.vars", $rdir."/db.vars.new");
    rename ($rdir."/db.vars.old", $rdir."/db.vars");
    rename ($rdir."/db.preprocessors", $rdir."/db.preprocessors.new");
    rename ($rdir."/db.preprocessors.old", $rdir."/db.preprocessors");
    rename ($rdir."/db.rules", $rdir."/db.rules.new");
    rename ($rdir."/db.rules.old", $rdir."/db.rules");
    $statusflag=$statusflag & 0xfffffffe;     
    $sqllog->execute($statusflag,$log,$sid);
    $sqllog->finish;
    return(0);
  }
}

sub outputvars {

my $sid=$_[0];
my $outdir=$_[1];
my $dbh=$_[2];


my $file=$outdir."/db.vars.new";
  open (FILE, ">$file") || die "Can't open output $file\n";
  $sql = $dbh->prepare("SELECT DISTINCTROW(vname), value, sid FROM rman_vars NATURAL JOIN rman_varvals WHERE sid=? OR sid=0 ORDER BY sid;");
  $sql->execute($sid);
  
  while(@resarray=$sql->fetchrow_array) {
      print FILE "var ".$resarray[0]." ".$resarray[1]."\n";
  }

  $sql->finish;
  close FILE;
  
}

sub outputpreprocessors {

my $sid=$_[0];
my $outdir=$_[1];
my $dbh=$_[2];


my $file=$outdir."/db.preprocessors.new";
  open (FILE, ">$file") || die "Can't open output $file\n";
  $sql = $dbh->prepare("SELECT DISTINCTROW(pname), options, sid FROM rman_preprocessors NATURAL JOIN rman_preprocessorvals WHERE sid=? OR sid=0 ORDER BY sid;");
  $sql->execute($sid);
  
  %vars=();  

  while(@resarray=$sql->fetchrow_array) {
      if( $resarray[1]) {
        print FILE "preprocessor ".$resarray[0].": ".$resarray[1]."\n";
      } else {
        print FILE "preprocessor ".$resarray[0]."\n";
      }
  }

  $sql->finish;
  close FILE;
  
}
sub outputrules {

my $sid=$_[0];
my $outdir=$_[1];
my $dbh=$_[2];

my $file=$outdir."/db.rules.new";

  open (FILE, ">$file") || die "Can't open output $file\n";
  $sql = $dbh->prepare("SELECT rman_rules.action, rman_rules.proto, rman_rules.s_ip, rman_rules.s_port, rman_rules.dir, rman_rules.d_ip, rman_rules.d_port,rman_rules.options from rman_rules, rman_rrgid, rman_senrgrp WHERE rman_senrgrp.sid=? AND rman_senrgrp.rgid=rman_rrgid.rgid AND rman_rrgid.rid=rman_rules.rid AND rman_rules.active='Y'");

  $sql->execute($sid);

  while(@resarray=$sql->fetchrow_array) {
    $resarray[7]="(".$resarray[7].")";
    $outstring=(join(" ",@resarray))."\n";
    print FILE $outstring;
  }
  $sql->finish;
  close FILE;
}

sub updated {
  my $sid=$_[0];
  my $dbh=$_[1];
  my $timefile=$_[2];
  my $oldtimestamp=0;

  my $sql = $dbh->prepare("SELECT updated FROM rman_sensor WHERE sid=?");
  $sql->execute($sid);

  if (!(($tstamp)=$sql->fetchrow_array)) {
    print "Sensor does not exist in RuleMANager tables\n";
    $sql->finish;
    exit(1);
  }  
  $sql->finish;

  open (CONFIG, "$timefile") || die "Can't open output $timefile\n";

  while (<CONFIG>) {
    chop;
    R_CONFIG: {
      /^## timestamp:\s*(\S+)\s*$/ && do {
      $oldtimestamp=$1;
      last R_CONFIG;
      };
    }
  }
  close CONFIG;
  if ($tstamp != $oldtimestamp) {
    open (CONFIG, ">$timefile") || die "Can't open output $timefile\n";
    printf CONFIG "## timestamp: $tstamp\n";
    close CONFIG;
    return(1);
  }
  else {
    return(0);
  }
}

sub logit {
  my $logstring=$_[0];
  my $now;
   
  $now=localtime(time);

  print "$now $logstring\n";
} 
