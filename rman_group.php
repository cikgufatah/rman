<?php
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

include_once("rman_common.inc");
include_once("rman_formclasses.inc");
include_once("rman_groupclasses.inc");

  global $debug;
  
  session_start();

  WriteHeader("Group Maintenance");

  $dbh=ConnectToDb();

  if ($debug) {
     print "<P>\n";
     print_r($_POST);
     print "</P>\n";
  }
  
  $finished=false;

  # Handle Group Create
  # Cancel does nothing - do default action
  if ($_POST["grpcreate"]) {
     if ($_POST["grpcreate"]=="Create") {
        grp_createnew();
	$finished=true;
     }
  }
  
  # Handle Group Modification
  if ($_POST["submit"]) {
    $submit=SanitizeUserInput($_POST["submit"]);
    $action=SanitizeUserInput($_POST["action_choice"]);
    switch ($action) {
      case "donothing":
        mod_group($_SESSION["rgid"]);
        break;

      case "activate":
        grp_change_rulestatus("Y",$_POST["rgroup_select"],$submit);
        mod_group($_SESSION["rgid"]);
        break;

      case "deactivate":
        grp_change_rulestatus("N",$_POST["rgroup_select"],$submit);
        mod_group($_SESSION["rgid"]);
        break;

      case "remove":
        grp_moverules(-1,$_POST["rgroup_select"],$submit);
        mod_group($_SESSION["rgid"]);
        break;

      case "delete":
        grp_deleterules($_POST["rgroup_select"],$submit);
	mod_group($_SESSION["rgid"]);
	break;

      case "addgroup":
      case "movegroup":
        # OK check what the user has entered and whether it is an integer or not
        $newrgid=SanitizeUserInput($_POST["action_entry"]);
        if (is_numeric($newrgid)) {
          
	  RunQuery($result,"SELECT rgid FROM rman_rgroup WHERE rgid='".$newrgid."'");
        }
        else {
          RunQuery($result,"SELECT rgid FROM rman_rgroup WHERE name='".$newrgid."'");
        }

        # If we've only got one row we have successfully identified the rulegroup the 
        # user intended so we can now move the rules .....
        if (mysqli_num_rows($result) == 1) {
           $row=mysqli_fetch_array($result, MYSQLI_ASSOC);
           $newrgid=$row["rgid"];
           if ($action=="movegroup") {
	     grp_moverules($newrgid,$_POST["rgroup_select"],$submit);
           }
	   else {
	     grp_addgroup($newrgid,$_POST["rgroup_select"],$submit);
	   }
	}
        else {
          PrintError("Invalid group entered - cannot move rules to ".$_POST["action_entry"]);
        }  

        mod_group($_SESSION["rgid"]);
        break;
             

      default:
        print"<BR>Invalid Input - Terminating Session</BR>\n";
        session_destroy();
    }   
  }
  else {
    if ($_GET['rgid']) {
      mod_group($_GET['rgid']);
    }
    else {
      if ($_GET['createnew']) {
        grp_Printcreatenew(); 

      }
      else {
        if (!$finished) list_groups();
      }
    } 
  }
  mysqli_close($dbh);


?>
    <HR>
  </BODY>
</HTML>


<?php
# Note an rgid of -1 means unassigned
#      a newrgid of -1 means delete

function grp_moverules($newrgid,$rulelist,$selonly) {
  global $_SESSION;
  global $debug;

  $rgid=$_SESSION["rgid"];
  $changes=false;

  foreach($rulelist as $rid => $selected) {
    if (($selected=="Y" && $selonly=="Selected") || $selonly=="All") {      
      if ($newrgid == -1) {                         # -1 for delete
        RunQuery($result,"DELETE FROM rman_rrgid WHERE rid='".mysqli_escape_string($rid)."' AND rgid='".$rgid."'"); 
      }
      else {
        if ($rgid != -1) {
          # Check to see if it is there already (if rgid is -1 it's unassigned so it can't be there!)...
          RunQuery($result,"SELECT rid FROM  rman_rrgid WHERE rid='".mysqli_escape_string($rid)."' AND rgid='".$newrgid."'");
          if (mysqli_num_rows($result) == 0) {
            RunQuery($result,"UPDATE rman_rrgid SET rgid='".$newrgid."' WHERE rid='".mysqli_escape_string($rid)."' AND rgid='".$rgid."'");
          }
          else {
            # OK, so if  it's already there - we need to delete if from here then!
            RunQuery($result,"DELETE FROM rman_rrgid WHERE rid='".mysqli_escape_string($rid)."' AND rgid='".$rgid."'"); 
          }
        }
        else {
          RunQuery($result,"INSERT INTO rman_rrgid (rid,rgid) VALUES ('".mysqli_escape_string($rid)."','".$newrgid."')");
        }
      }
      $changes=true;
    }
  }
  if ($changes==true) {
    if ($rgid !=-1) Group_UpdateTimeStamps($rgid);
    if ($newrgid != -1) Group_UpdateTimeStamps($newrgid);
  }
}

function grp_addgroup($newrgid,$rulelist,$selonly) {
  global $_SESSION;
  global $debug;

  $changes=false;    
  foreach($rulelist as $rid => $selected) {
    if (($selected=="Y" && $selonly=="Selected") || $selonly=="All") {      
      # Check to see if it is there already ...
      RunQuery($result,"SELECT rid FROM  rman_rrgid WHERE rid='".mysqli_escape_string($rid)."' AND rgid='".$newrgid."'");
      # Zero rows means it's not there so we can add it
      if (mysqli_num_rows($result) == 0) {
        RunQuery($result,"INSERT INTO rman_rrgid (rid,rgid) VALUES ('".mysqli_escape_string($rid)."','".$newrgid."')");
        $changes=true;
      }
    }
  }
  if ($changes==true)  Group_UpdateTimeStamps($newrgid);
}

function grp_deleterules($rulelist,$selonly) {

  if ($selonly=="All") {
    PrintError("Delete 'All' is not a safe thing to do - action refused");
  }
  else {
    foreach($rulelist as $rid => $selected) {
      if ($selected=="Y") {
        # Check to see that the rule really doesn't have an entry in any group (belt & braces)
        RunQuery($result,"SELECT rgid FROM  rman_rrgid WHERE rid='".mysqli_escape_string($rid)."'");
        if (mysqli_num_rows($result) == 0) {
          RunQuery($result,"DELETE FROM rman_rules WHERE rid='".mysqli_escape_string($rid)."'");
        }
        else {
          PrintError("Rule ID ".addslashes($rid)." is still active - it cannot be deleted");
        }
      }
    }
  }
}

function grp_change_rulestatus($status,$rulelist,$selonly) {
  global $_SESSION;
  global $debug;
 
  $rgid=$_SESSION["rgid"];
  # Defang User Input
  if (!is_numeric($rgid)) {
    PrintError("Invalid Input");
    return;
  }
  $rgid=mysqli_escape_string($rgid);

  $rgroup=new rgroup($rgid);
  $members=$rgroup->members;
  $changes=false;

  if ($debug) print_r($rulelist);  
  
  foreach($rulelist as $rid => $selected) {
    if (($selected=="Y" && $selonly=="Selected") || $selonly=="All") {
      if ($status != $members[$rid]->active) {
        RunQuery($result,"UPDATE rman_rules SET active='".$status."' WHERE rid = '".$rid."'");
        $changes=true;      
      }
    }
  }
  if ($changes==true AND $rgid != -1) {
    Group_UpdateTimeStamps($rgid);
  }
}

function mod_group($rgid) {
  global $_SESSION, $dbh;
  # Defang User Input
  if (!is_numeric($rgid)) {
    PrintError("Invalid Input");
    return;
  }
  $rgid=mysqli_escape_string($dbh, $rgid);
  
 
  $rgroup=new rgroup($rgid);

  $info=new html_tableform();
  $info->tabletitle="Rule Group:&nbsp;".$rgroup->name;
  $info->AddRowElem(new html_RowElem("Total Rules: ".count($rgroup->members),"LEFT")); $info->EndRow();
  $info->AddRowElem(new html_RowElem("<A HREF=\"{$_SERVER['PHP_SELF']}\">List Groups</A>" ,"LEFT")); $info->EndRow();
  if ($rgid != -1) {
    $info->AddRowElem(new html_RowElem("<A HREF=\"rman_sensor.php?senwgrp=".$rgid."\">Sensors using this group</A>" ,"LEFT")); $info->EndRow();
  }
  $info->Print_HTML_Table();

  $form=grp_buildtable($rgroup); 
  if ($rgid != -1) {
    $form->AddActionChooser(array("donothing" => "{Select Action}", "activate" => "Activate","deactivate" => "Deactivate","addgroup" => "Add to Group", "remove" => "Remove from group", "movegroup" => "Move to Group"));
  }
  else {
    $form->AddActionChooser(array("donothing" => "{Select Action}", "activate" => "Activate","deactivate" => "Deactivate", "movegroup" => "Move to Group","delete" => "Delete"));
  }
  $form->AddActionEntry();
  $form->AddAction("Selected","submit","submit");
  $form->AddAction("All","submit","submit");
  $form->height="400px";
  $form->Print_HTML();
  
  $_SESSION["rgid"]=$rgid;
}

function grp_buildtable($rgroup) {
  
  $form=new html_tableform("GroupRulesForm","post","{$_SERVER['PHP_SELF']}");
  $form->outertable=true;
  $form->stripe=true;

  $form->AddColumn(" ID ","plfieldhdr",6);
  $form->AddColumn(" Name ","plfieldhdrleft",44);
  $form->AddColumn(" Rev ","plfieldhdr",3);
  $form->AddColumn(" Created ","plfieldhdr",17);
  $form->AddColumn(" Updated ","plfieldhdr",17);
  $form->AddColumn(" Active ","plfieldhdr",5);
  $form->AddColumn(" Select&nbsp;","plfieldhdr",6);

  foreach ($rgroup->members AS $rid => $member) {
    $form->AddRowElem(new html_RowElem("&nbsp;&nbsp;" . $rid,"CENTER"));
    $form->AddRowElem(new html_RowElem("<font><A HREF='rman_rule.php?rid=" . $rid . "'>".$member->name."</font>&nbsp;","LEFT"));
    $form->AddRowElem(new html_RowElem("&nbsp;&nbsp;" . $member->rev,"CENTER"));
    $form->AddRowElem(new html_RowElem("&nbsp;&nbsp;" . $member->created,"CENTER"));
    $form->AddRowElem(new html_RowElem("&nbsp;&nbsp;" . $member->updated,"CENTER"));
    $form->AddRowElem(new html_RowElem("&nbsp;&nbsp;" . $member->active,"CENTER"));
    $form->AddRowElem(new html_RowElemTickBox($rid,"rgroup_select",'N'));
    $form->EndRow();
  }

  return($form);

}

function grp_Printcreatenew($name="", $desc="") {
  $form = new html_tableform("GroupCreateNew","post","{$_SERVER['PHP_SELF']}");
  $form->tabletitle="Create New Group";
  $form->width=60;

  $form->AddAction("Create","grpcreate","submit");
  $form->AddAction("Cancel","grpcreate","submit");

  $form->AddRowElem(new html_RowElem("Group Name","LEFT","")); 
  $form->AddRowElem(new html_RowElem($name,"LEFT","","name",30));
  $form->EndRow();
  $form->AddRowElem(new html_RowElem("Description","LEFT","")); 
  $form->AddRowElem(new html_RowElem($desc,"LEFT","","description",40));
  $form->EndRow();
  $form->Print_HTML();
}

function grp_createnew() {
  global $_POST;

  $name=SanitizeUserInput($_POST["name"],"plaintext",30);
  $desc=SanitizeUserInput($_POST["description"],"description",255);

  # Check name doesn't exist
  RunQuery($result,"SELECT rgid FROM rman_rgroup WHERE name='".$name."'");
  
  if (mysqli_num_rows($result)!=0) {
    PrintError("Group Already Exists");
    grp_Printcreatenew($name,$desc);
  }
  else {
    RunQuery($result,"INSERT INTO rman_rgroup (name,description) VALUES ('".$name."','".$desc."')");
    print "<P><B>Created Group:</B> ".$name."</P>\n";
    list_groups();
  }

}

function list_groups() {
  RunQuery($groups,"SELECT rgid,name,description FROM rman_rgroup ORDER BY name");

  print "<P><A HREF='{$_SERVER['PHP_SELF']}?rgid=-1'>Show Unassigned Rules</A>\n";
  print "<BR><A HREF=\"{$_SERVER['PHP_SELF']}?createnew=1\">Create New Group</A></P>\n";

  print "\n<TABLE BORDER=0 CELLSPACING=0 CELLPADDING=0 BGCOLOR='#FFFFFF' >\n";

  print "<TR>\n";
  print "<TD CLASS='plfieldhdrleft' WIDTH='35%'> Group Name </TD>\n";
  print "<TD CLASS='plfieldhdrleft' WIDTH='50%'> Description </TD>\n";
  print "</TR>\n";
  $odd=0;
  while ($row = mysqli_fetch_array($groups, MYSQLI_ASSOC)) {
    PRINT "<TR BGCOLOR='".ColourOddEven($odd)."'>\n";
    print "\t<TD ALIGN=LEFT><font>&nbsp;<A HREF='{$_SERVER['PHP_SELF']}?rgid=" . $row["rgid"] . "'>".$row["name"]."&nbsp;</TD>\n";
    print "\t<TD ALIGN=LEFT>&nbsp;&nbsp;" . $row["description"] . "</TD>\n";
    print "</TR>\n";
  }
  print "</TABLE>\n";
}

?>
