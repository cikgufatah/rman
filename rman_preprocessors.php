<?php
# --------------------------------------------------------------------------
# Copyright (C) 2002 SecureCiRT, A SBU of Z-Vance Pte Ltd
# Author: Michael Boman <michael.boman@securecirt.com>
# Portions Copyright Mark Vevers <mark@vevers.net>
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

include_once("rman_common.inc");
include_once("rman_formclasses.inc");

  global $debug;
  session_start();

  $handled=false;

  $dbh=ConnectToDb();
  $debug=0;

  if ($debug) {
     print "<P>\n";
     print_r($_GET);
     print "<BR>\n";
     print_r($_POST);
     print "<BR>\n";
     print_r($_SESSION);
     print "</P>\n";
  }

  if (isset($_POST['showpid_submit']) && !$handled) {
    $svsubmit=SanitizeUserInput($_POST['showpid_submit'],"plaintext");
    if ($debug) print "<BR>$svsubmit\n";
    
    $pid=SanitizeUserInput($_GET['pid'],"int",11,$modified);
    
    switch ($svsubmit) {
      case "AddNewfor":
        if (!$modified) $sid=SanitizeUserInput($_POST['action_choice'],"int",11,$modified);
	if (!$modified) { 
	  preprocessors_sv_addnew($pid,$sid);
        }
	else {
	  PrintError("Invalid Submission Received for Add New");
	}
	break;

      case "DeleteSelected":
	if (!$modified) preprocessors_sv_delete($pid,$_POST['showpid_select']);
	break;

      case "Update":
        if (!$modified) preprocessors_updatedefaults($pid,$_POST['defoptions'],$_POST['defcomment']);
        break;
       
      case "Delete":
        if (!$modified) preprocessors_deletepreprocessor($pid);
        # this pid just bit the dust so we can't display it - return to show_main
	unset($_GET['pid']);
	break;
      
      case "UpdateSensors":
        if (!$modified) preprocessors_updatesenpreprocessors($pid,$_POST['pid_val'],$_POST['pid_com']);
        break;
	
      default:
      PrintError("Invalid Submission Received");
    }
      
  }

  if (isset($_GET['pid']) && !$handled) {
     $pid=SanitizeUserInput($_GET['pid'],"int",11,$modified);
     if ((!$modified) && $pid!=0) {
       preprocessors_showpid($pid);
       $handled=true;
     }
     else {
       PrintError("Invalid User Input Detected");
     }
  }
  
  if (isset($_POST['create_submit']) && !$handled) {
    $createsubmit=SanitizeUserInput($_POST['create_submit'],"plaintext");
    switch ($createsubmit) {
      case "Create":
        $handled=preprocessors_createnew($_POST['name'],$_POST['options'],$_POST['comment']);
        break;
    
      case "Cancel":
        break;
      default:
      PrintError("Invalid Submission Received");
    }
  }

  if (isset($_POST['main_submit']) && !$handled) {
    $mainsubmit=SanitizeUserInput($_POST['main_submit'],"plaintext");
    switch ($mainsubmit) {
      case "CreateNew":
        preprocessors_showcreatenew();
	$handled=true;
      break;
      case "DeleteSelected":
        if (isset($_POST['preprocessors_select'])) preprocessors_maindelselect($_POST['preprocessors_select']);
        break; 
      default:
      PrintError("Invalid Submission Received");
    }
  }
  
  if (!$handled) {
     preprocessors_showmain();
  }

  mysqli_close($dbh);
?>
    <HR>
  </BODY>
</HTML>


<?php

function preprocessors_deletepreprocessor($pid) {
  if ($pid>=100) {
    RunQuery($result,"DELETE FROM rman_preprocessors WHERE pid='".$pid."'");
    RunQuery($result,"DELETE FROM rman_preprocessorvals WHERE pid='".$pid."'");
    UpdateAllActiveSensors();
  }
}

function preprocessors_updatedefaults($pid,$options,$comment) {
  preprocessors_sv_sessinit($pid,$sensors,$defaults,$senvars,$restored);
  
  $modified=!$restored;
  if (!$modified) $options=SanitizeUserInput($options,"snort_ip",255,$modified);
  if (!$modified) $comment=SanitizeUserInput($comment,"description",255,$modified);
  if (!$modified) {
    if (($options != $defaults->options) || ($comment != $defaults->comment)) {
      preprocessors_update($pid,0,$options,$comment);
      
      # Now Get List of  Sensors which use default and update timestampes
      RunQuery($senslist,"SELECT rman_sensor.sid FROM rman_sensor LEFT JOIN rman_preprocessorvals ON (rman_sensor.sid=rman_preprocessorvals.sid AND pid='".$pid."') WHERE rman_preprocessorvals.sid IS NULL");
      UpdateSensorTimeStamps($senslist);
      
      if (session_is_registered("s_pid")) session_unregister("s_pid");
    }
  }
  if ($modified) {
     printerror("Invalid User Input Detected $options - $comment");
  }
}

function preprocessors_updatesenpreprocessors($pid,$optionss,$comments) {
  preprocessors_sv_sessinit($pid,$sensors,$defaults,$senvars,$restored);
  if (count($optionss) && $restored) {
    $updated=false;
    foreach($optionss AS $sid => $options) {
      $sid=SanitizeUserInput($sid,"int",11,$modified); 
      if (($sid!=0) && !$modified) {
        $options=SanitizeUserInput($options,"snort_ip",255,$modified);
        if (!$modified) $comment=SanitizeUserInput($comments[$sid],"description",255,$modified);
	if ((($senvars[$sid]->options!=$options) || ($senvars[$sid]->comment!=$comment)) && !$modified)  {
          preprocessors_update($pid,$sid,$options,$comment);
	  UpdateSensorTime_Sid($sid);
	  $updated=true;
	}
      }
      if ($modified) printerror ("Failed update for".$sensors[$sid].". Invalid User Input Detected");
    }
    if ($updated) {
      if (session_is_registered("s_pid")) session_unregister("s_pid");
    }
  }

  if (!$restored) printerror("Unable to restore session - can't update preprocessors");
}


function preprocessors_update($pid,$sid,$options,$comment) {
  RunQuery($result,"UPDATE rman_preprocessorvals SET options='".mysqli_escape_string($options)."', comment='".mysqli_escape_string($comment)."' WHERE pid='".$pid."' AND sid='".$sid."'");
}

function preprocessors_sv_delete($pid,$selected) {

  $deleted=false;
  
  preprocessors_sv_sessinit($pid,$sensors,$defaults,$senvars,$restored);

  if ($restored) {
    foreach($selected as $sid => $select) {
      $sid=SanitizeUserInput($sid,"int",11,$modified);
      if (!$modified && $sid!=0 && $select=='Y') {
         RunQuery($result,"DELETE FROM rman_preprocessorvals WHERE sid='".$sid."' AND pid='".$pid."'");
         $deleted=true;
	 UpdateSensorTime_Sid($sid);
      }
    }
  }
  if ($deleted || !$restored) session_unregister("s_pid");
}

function preprocessors_sv_addnew($pid,$sid) {
  if ($sid==0) {
    PrintError("Please Select A Sensor!");
    return;
  }

  preprocessors_sv_sessinit($pid,$sensors,$defaults,$senvars,$restored);

  if ($restored) {
    if (!isset($senvars[$sid])) {
      # OK - there shouldn't be a preprocessor present according to the session
      # but we had better check just in case someone else is tinkering!

      RunQuery($result,"SELECT options FROM rman_preprocessorvals WHERE sid='".$sid."' AND pid='".$pid."'");
      if (mysqli_num_rows($result)==0) {
         RunQuery($result,"INSERT INTO rman_preprocessorvals (pid,sid,options,comment) VALUES ('".$pid."','".$sid."','".$defaults->options."','".$defaults->comment."')");
      }
      else {
        PrintError("Somebody else added the preprocessor for this sensor while you weren't looking!");
      }
      session_unregister("s_pid");      # Unregister s_pid to force preprocessor refresh to pick up new one!
    }
    else {
      PrintError("Sensor already has preprocessor defined - can't add new!");
    }
  }
  else {
    PrintError("Session Error - Clearing Session");
    session_unregister("s_pid");
  }
}

function preprocessors_sv_sessinit(&$pid,&$sv_sensors,&$sv_defdata,&$sv_senvars,&$ses_restored=false) {
  global $_SESSION;
  $ses_restored=false;
  if (isset($_SESSION["s_pid"])) {
    $s_pid=$_SESSION["s_pid"];
    if ($s_pid == $pid) {
      $sv_sensors=$_SESSION["sv_sensors"];
      $sv_defdata=$_SESSION["sv_defdata"];
      $sv_senvars=$_SESSION["sv_senvars"];
      $ses_restored=true;
    }
  }

  if (!$ses_restored) {
    //if (!session_is_registered("s_pid")) session_register("s_pid");
    //if (!session_is_registered("sv_sensors")) session_register("sv_sensors");
    //if (!session_is_registered("sv_defdata")) session_register("sv_defdata");
    //if (!session_is_registered("sv_senvars")) session_register("sv_senvars");
    
    $_SESSION["s_pid"]=$pid;

    # Get Default options and check preprocessor exists
    RunQuery($result,"SELECT pname,options,comment,updated FROM rman_preprocessors,rman_preprocessorvals WHERE rman_preprocessors.pid=rman_preprocessorvals.pid AND sid=0 AND rman_preprocessors.pid='".$pid."'");
    if (mysqli_num_rows($result)==0) {
      PrintError("Invalid preprocessor identifier given");
      session_unset("s_pid");
      $pid=0;
      return;
    }
    $sv_defdata = mysqli_fetch_object($result);
    $_SESSION["sv_defdata"]=$sv_defdata;
    
    # Populate sv_sensors
    RunQuery($allsensres,"SELECT rman_sensor.sid, hostname, interface FROM sensor, rman_sensor WHERE rman_sensor.sid = sensor.sid");
    $sv_sensors=array();
    while ($row = mysqli_fetch_object($allsensres)) {
      $sv_sensors[$row->sid]=$row->hostname." - ".$row->interface;
    }
    $_SESSION["sv_sensors"]=$sv_sensors;

    # Get sensor specific preprocessor into array
    $sv_senvars=array();
    RunQuery($senres,"SELECT sid, options, comment, updated FROM rman_preprocessors, rman_preprocessorvals WHERE rman_preprocessors.pid=rman_preprocessorvals.pid AND sid != 0 AND rman_preprocessors.pid='".$pid."' ORDER BY sid");
    while ($senvar = mysqli_fetch_object($senres)) {
      $sv_senvars[$senvar->sid]=$senvar;
    }
    $_SESSION["sv_senvars"]=$sv_senvars;
  }
}

function preprocessors_showpid($pid) {
  # pid has been sanitized to be a postive integer  only before entry to 
  # this procedure.  Further checking it not required.
  
  WriteHeader("Preprocessor Maintenace - Preprocessor Definition");

  # Initialize the session
  preprocessors_sv_sessinit($pid,$sensors,$defdata,$senvars);
  
  # $pid=0 if invalid $pid passed
  if ($pid==0) return;

  print "<H2>Preprocessor: ".$defdata->pname."</H2>\n";
  print "<A HREF='{$_SERVER['PHP_SELF']}'>Return to Preprocessor Maintenance</A>\n";

  $defaults = new html_tableform("preprocessor_view","post","{$_SERVER['PHP_SELF']}?pid=".$pid);

  # Add delete option if no sensors have their own copy of this preprocessor
  if (count($senvars)==0) $defaults->AddAction("Delete","showpid_submit","submit");
  $defaults->AddAction("Update","showpid_submit","submit");
  $defaults->width=55;
 
  
  $rowelem=new html_RowElem("Options&nbsp;","LEFT","");
  $rowelem->width="25%";
  $defaults->AddRowElem($rowelem);
  $defaults->AddRowElem(new html_RowElem($defdata->options,"LEFT","","defoptions",60,255));
  $defaults->EndRow();
  
  $defaults->AddRowElem(new html_RowElem("Comment&nbsp;","LEFT",""));
  $defaults->AddRowElem(new html_RowElem($defdata->comment,"LEFT","","defcomment",60,255));
  $defaults->EndRow();
  
  $var_sens = new html_tableform();
  $var_sens->outertable=true;
  $var_sens->stripe=true;
  $var_sens->width=80;

  $var_sens->AddAction("Add New for","showpid_submit","submit");
  $sensors[0]="{Select Sensor}";
  $var_sens->AddActionChooser($sensors); 
  $var_sens->AddAction("Delete Selected","showpid_submit","submit");
  $var_sens->AddAction("Update Sensors","showpid_submit","submit");

  $var_sens->AddColumn(" Sensor ","plfieldhdrleft",25);
  $var_sens->AddColumn(" Options ","plfieldhdrleft",35);
  $var_sens->AddColumn(" Comment ","plfieldhdrleft",35);
  $var_sens->AddColumn(" Select ","plfieldhdr",5);
  
  if (count($senvars)) {
    foreach ($senvars as $senvar) {
      $var_sens->AddRowElem(new html_RowElem($sensors[$senvar->sid],"LEFT",""));
      $var_sens->AddRowElem(new html_RowElem($senvar->options,"LEFT","","pid_val[".$senvar->sid."]",40,255));
      $var_sens->AddRowElem(new html_RowElem($senvar->comment,"LEFT","","pid_com[".$senvar->sid."]",40,255));
      $var_sens->AddRowElem(new html_RowElemTickBox($senvar->sid,"showpid_select",'N'));
      $var_sens->EndRow();
    }
  }

  $defaults->Print_HTMLhdr();
  print "<P><H2>Defaults</H2>\n";
  $defaults->Print_HTML_Actions();
  $defaults->Print_HTML_Table();
  $defaults->Print_HTMLexports();
  print "</P><BR>\n";

  print "<P><H2>Per Sensor Variations</H2>\n";
  $var_sens->Print_HTML_Actions();
  $var_sens->Print_HTML_Table();
  print "</P>\n";
  
  print "</FORM>\n";
  
}

function preprocessors_createnew($name, $options, $comment) {
  $name=SanitizeUserInput($name,"plaintext",30,$modname);
  $options=SanitizeUserInput($options,"snort_ip",255,$modval);
  $comment=SanitizeUserInput($comment,"description",255,$modcomment);

  # OK - if vars were modified return the page with edited vars on and ask user to confirm
  if ($modname || $modval || $modcomment) {
    preprocessors_showcreatenew($name,$options,$comment,"Invalid User Input Removed - Click 'Create' to confirm creation");
    return(true);
  }
  
  # We have clean vars so check to see if name already exists
  RunQuery($result,"SELECT pid FROM rman_preprocessors WHERE pname='".$name."'");
  if (mysqli_num_rows($result)!=0) {
    preprocessors_showcreatenew($name,$options,$comment,"Preprocessor Already Exists");
    return(true);
  }
  
  # Ok, it doesn't - lets create it ......
  RunQuery($result,"INSERT INTO rman_preprocessors (pname) VALUES ('".$name."')");
  $pid=mysqli_insert_id();
  RunQuery($result,"INSERT INTO rman_preprocessorvals (pid,sid,options,comment) VALUES ('".$pid."', 0, '".mysqli_escape_string($options)."','".mysqli_escape_string($comment)."')");
  # Now update sensors ....
  UpdateAllActiveSensors();
  return(false);
}


function preprocessors_showcreatenew($name="",$options="Default Options",$comment="Default Comment",$errmess="") {
  WriteHeader("Preprocessor Maintenace - Create New");

  if ($errmess != "") PrintError($errmess);
  
  print "<P><H2>Create New Preprocessor\n";
  $newvar = new html_tableform("var_createnew","post",$_SERVER['PHP_SELF']);
  $newvar->AddAction("Create","create_submit","submit");
  $newvar->AddAction("Cancel","create_submit","submit");
  $newvar->width=55;
  
  $rowelem=new html_RowElem("Name&nbsp;","LEFT","");
  $rowelem->width="25%";
  $newvar->AddRowElem($rowelem);
  $newvar->AddRowElem(new html_RowElem($name,"LEFT","","name",30,30));
  $newvar->EndRow();
  
  $newvar->AddRowElem(new html_RowElem("Options&nbsp;","LEFT",""));
  $newvar->AddRowElem(new html_RowElem($options,"LEFT","","options",30,255));
  $newvar->EndRow();

  $newvar->AddRowElem(new html_RowElem("Comment&nbsp;","LEFT",""));
  $newvar->AddRowElem(new html_RowElem($comment,"LEFT","","comment",60,255));
  $newvar->EndRow();
	      
  $newvar->Print_HTML();
  print "</P>\n";
}

function preprocessors_maindelselect($selected) {
  foreach($selected AS $pid => $select) {
    if ($select=='Y') {
      $pid=SanitizeUserInput($pid,"int",11,$modified);
    
      if (!$modified) {
        RunQuery($senres,"SELECT pname FROM rman_preprocessors, rman_preprocessorvals WHERE rman_preprocessors.pid=rman_preprocessorvals.pid AND sid != 0 AND rman_preprocessors.pid='".$pid."' ORDER BY sid");
	if (mysqli_num_rows($senres)==0) {
	  preprocessors_deletepreprocessor($pid);
	}
	else {
	  $ivn = mysqli_fetch_object($senres);
	  printerror("Unable to delete variable: ".$ivn->pname." - Per Sensor Variations Still Exist!");
	}
      }
    }
  }
}

function preprocessors_showmain() {
  WriteHeader("Preprocessor Maintenace");

  print "<P><H2>Default Preprocessors</H2></P>\n";

  $preprocessors = new html_tableform("preprocessor_summary","post",$_SERVER['PHP_SELF']);
  $preprocessors->outertable=true;
  $preprocessors->stripe=true;
  $preprocessors->AddAction("Create New","main_submit","submit"); 
  $preprocessors->AddAction("Delete Selected","main_submit","submit"); 
 
  $preprocessors->AddColumn("Preprocessor","plfieldhdrleft",15);
  $preprocessors->AddColumn("Default Options","plfieldhdrleft",40);
  $preprocessors->AddColumn("Comment","plfieldhdrleft",40);
  $preprocessors->AddColumn("Select","plfieldhdr",5);

  RunQuery($result,"SELECT rman_preprocessors.pid, pname,options,comment FROM rman_preprocessors NATURAL JOIN rman_preprocessorvals WHERE sid=0 ORDER BY rman_preprocessors.pid"); 
 
  While ($row = mysqli_fetch_object($result)) {
    $preprocessors->AddRowElem(new html_RowElem("&nbsp;<font><A HREF='{$_SERVER['PHP_SELF']}?pid=" . $row->pid . "'>".$row->pname."</font>&nbsp;","LEFT"));
    $val=substr($row->options,0,45).((strlen($row->options) > 45) ? " ..." : "");
    $preprocessors->AddRowElem(new html_RowElem("&nbsp;" . $val,"LEFT")); 
    $preprocessors->AddRowElem(new html_RowElem("&nbsp;" . $row->comment,"LEFT")); 
    $preprocessors->AddRowElem(new html_RowElemTickBox($row->pid,"preprocessors_select",'N'));
    $preprocessors->EndRow();
  }
  $preprocessors->Print_HTML();
}
?>
