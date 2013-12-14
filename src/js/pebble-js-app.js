var timeoffset = 0;
var numkeys = 0;
var keynames = "";
var keyvalues = "";

function logVariables() {
	console.log("	timeoffset: " + timeoffset);
	console.log("	keynames: " + keynames);
	console.log("	keyvalues: " + keyvalues);
}

Pebble.addEventListener("ready", function() {
	console.log("Ready Event");
	
	timeoffset = (new Date()).getTimezoneOffset();
	
	var names = new Array();
	keynames = localStorage.getItem("keynames");
	if (!keynames) {
		keynames = "";
	} else {
		names = keynames.split("|");
	}
	
	var keys = new Array();
	keyvalues = localStorage.getItem("keyvalues");
	if (!keyvalues) {
		keyvalues = "";
	} else {
		keys = keyvalues.split("|");
	}
	
	numkeys = names.length;
	
	if (names.length != keys.length) {
		console.log("	ERROR: " + names.length + " key names but " + keys.length + " keys!");
	}
	
	logVariables();
						
	Pebble.sendAppMessage(JSON.parse('{"timeoffset":'+timeoffset+',"keynames":"'+keynames+'","keyvalues":"'+keyvalues+'"}'));
});

Pebble.addEventListener("showConfiguration", function(e) {
	console.log("showConfiguration Event");

	logVariables();
						
	var URL = "http://www.famillemattern.com/jnm/pebble/Authenticator/Authenticator_2.0.0.php?keynames=" +
						encodeURIComponent(keynames) + "&keyvalues=" + encodeURIComponent(keyvalues);
						
	Pebble.openURL(URL);
});

Pebble.addEventListener("webviewclosed", function(e) {
	console.log("Configuration window closed");
	console.log(e.type);
	console.log(e.response);

	if (e.response) {
		var configuration = JSON.parse(decodeURIComponent(e.response));
		configuration['keynames'] = configuration['keynames'].replace('+', ' ');
		Pebble.sendAppMessage(configuration);
		
		keynames = configuration["keynames"];
		localStorage.setItem("keynames", keynames);
		
		keyvalues = configuration["keyvalues"];
		localStorage.setItem("keyvalues", keyvalues);

		timeoffset = configuration["timeoffset"];
		localStorage.setItem("timeoffset", timeoffset);
	}
});
