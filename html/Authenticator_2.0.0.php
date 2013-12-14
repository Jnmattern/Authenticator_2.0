<!DOCTYPE html>
<html>
        <head>
                <title>Authenticator</title>
                <meta charset='utf-8'>
                <meta name='viewport' content='width=device-width, initial-scale=1'>
                <link rel='stylesheet' href='http://code.jquery.com/mobile/1.3.2/jquery.mobile-1.3.2.min.css' />
                <script src='http://code.jquery.com/jquery-1.9.1.min.js'></script>
                <script src='http://code.jquery.com/mobile/1.3.2/jquery.mobile-1.3.2.min.js'></script>
                <style>
                        .ui-header .ui-title { margin-left: 1em; margin-right: 1em; text-overflow: clip; }
                </style>
        </head>
		<body>
<div data-role="page" id="page1">
    <div data-theme="a" data-role="header" data-position="fixed">
        <h3>
            Authenticator Configuration
        </h3>
        <div class="ui-grid-a">
            <div class="ui-block-a">
                <input id="cancel" type="submit" data-theme="c" data-icon="delete" data-iconpos="left"
                value="Cancel" data-mini="true">
            </div>
            <div class="ui-block-b">
                <input id="save" type="submit" data-theme="b" data-icon="check" data-iconpos="right"
                value="Save" data-mini="true">
            </div>
        </div>
    </div>
    <div id="keys" data-role="content"></div>

    <script>
<?php
	$keynames = array("");
	$keyvalues = array("");
	$numkeys = 1;
	$numkeynames = 1;
	$numkeyvalues = 1;
	
	if (isset($_GET["keynames"])) {
		$keynames = explode("|", urldecode($_GET["keynames"]));
		$numkeynames = count($keynames);
	}
	
	if (isset($_GET["keyvalues"])) {
		$keyvalues = explode("|", urldecode($_GET["keyvalues"]));
		$numkeyvalues = count($keyvalues);
	}
	
	if ($numkeynames != $numkeyvalues) {
		$numkeys = 1;
	} else {
		$numkeys = $numkeynames;
	}
	
	echo "		var numkeys = " . $numkeys . ";\n";
	echo "		var keynames = new Array();\n";
	echo "		var keyvalues = new Array();\n";
		
	for ($i=0; $i<$numkeys; $i++) {
		echo "		keynames[" . $i . "] = '" . $keynames[$i] . "';\n";
		echo "		keyvalues[" . $i . "] = '" . $keyvalues[$i] . "';\n";
	}
?>

		function displayFields() {
			var html = '';
			for (i=1; i<=numkeys; i++) {
				html += '<div data-role="fieldcontain"><label for="keyname' + i + '">Key ' + i + ' - Name</label>';
				html += '<input name="keyname' + i + '" id="keyname' + i + '" placeholder=""';
				html += ' value="' + (i <= keynames.length?keynames[i-1]:'') + '" data-mini="true" type="text"></div>';
				html += '<div data-role="fieldcontain"><label for="keyval' + i + '">Key ' + i + ' - Key</label>';
				html += '<input name="keyval' + i + '" id="keyval' + i + '" placeholder=""';
				html += ' value="' + (i <= keyvalues.length?keyvalues[i-1]:'') + '" data-mini="true" type="text"></div>';
			}

			html += '<div class="ui-grid-a"><div class="ui-block-a">';
			if (numkeys > 1) {
				html += '<a id="rmkey" data-role="button" data-theme="c" href="#page1" data-icon="minus" data-iconpos="left">Remove Key</a>';
			}
			html += '</div><div class="ui-block-b">';
			if (numkeys < 4) {
				html += '<a id="addkey" data-role="button" data-theme="b" href="#page1" data-icon="plus" data-iconpos="left">Add Key</a>';
			}
			html += '</div></div>';
			
			$("#keys").html(html);
			$("#keys").trigger('create');
			
			$("#addkey").click(function() {
				numkeys++;
				displayFields();
			});
			
			if (numkeys > 1) {
				$("#rmkey").click(function() {
					numkeys--;
					displayFields();
				});
			}
		}
		
		function saveOptions() {
			keynames = '';
			keyvalues = '';
			for (i=1; i<=numkeys; i++) {
				var keynotempty = ($("#keyname"+i).val().length > 0) || ($("#keyval"+i).val().length > 0);
				
				if (keynotempty) {
					if (i > 1) {
						keynames += "|";
						keyvalues += "|";
					}
					keynames += $("#keyname"+i).val();
					keyvalues += $("#keyval"+i).val();
				}
			}
			
			var options = {
				'keynames': keynames,
				'keyvalues': keyvalues,
				'timeoffset': (new Date()).getTimezoneOffset()
			}
			
			return options;
		}

		$().ready(function() {
			$("#cancel").click(function() {
				console.log("Cancel");
				document.location = "pebblejs://close#";
			});

			$("#save").click(function() {
				console.log("Submit");

				var location = "pebblejs://close#" + encodeURIComponent(JSON.stringify(saveOptions()));
				console.log("Close: " + location);
				console.log(location);
				document.location = location;
			});

			displayFields();
		});
    </script>
    </div>
</body>
</html>
