
(function () {

    'use strict';

    ////////////////////////////////////////////////////////////////////////////////
    
    // Make it hard to get the secret key once a passphrase has been entered
    var nacl = window.nacl;
    var Uint8Array = window.Uint8Array;
    window.nacl = undefined;

    // attempt to prevent tampering, though not as important or
    // feasible as the secret key protection
    var Uint16Array = window.Uint16Array;
    var Uint32Array = window.Uint32Array;

    var words = window.words;
    var Base58 = window.Base58;

    window.words = undefined;
    window.Base58 = undefined;

    delete window.nacl;
    delete window.words;
    delete window.Base58;

    ////////////////////////////////////////////////////////////////////////////////
    // Setup 1

    function passphraseConfirmChange() {
	var displayed = document.getElementById('passphrase').textContent;
	var typed = document.getElementById('passphrase-confirm').value;
	if (displayed === typed) {
	    document.getElementById('passphrase-continue').style.display = 'block';
	} else {
	    document.getElementById('passphrase-continue').style.display = 'none';
	}
	return false;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // Setup 2

    function focusContactEmail() {
	document.getElementById('contact-email').focus();
    }

    var passphrase = null;
    function passphraseContinue() {
	passphrase = document.getElementById('passphrase').textContent;
	document.getElementById('passphrase').textContent = '';
	document.getElementById('passphrase-confirm').value = '';

	document.getElementById('setup1-box').style.display = 'none';
	document.getElementById('setup2-box').style.display = 'block';

	setTimeout(focusContactEmail, 0);
	
	document.getElementById('contact-continue').onclick = contactContinue;

	return false;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // Setup 3

    function eB58(b) {
	return Base58.encode(b);
    }

    function taggedB58Key(b) {
	var tagged = new Uint8Array(nacl.box.publicKeyLength + 1);
	tagged.set(b, 1);
	tagged[0] = nacl.hash(b)[0] & 127;
	return eB58(tagged);
    }

    function getLink(passphrase, email, twitter) {
	var keyPair = nacl.box.keyPair.fromSecretKey(nacl.hash(nacl.util.decodeUTF8(passphrase)).subarray(0, nacl.box.secretKeyLength));
	var url = 'https://scrambl.is/write/' + taggedB58Key(keyPair.publicKey) + "?v=1";
	if (email) {
	    url += '&email=' + encodeURIComponent(email).replace(/%40/g, '@');
	}
	if (twitter) {
	    if (twitter[0] === '@') {
		twitter = twitter.substring(1);
	    }
	    url += '&twitter=' + encodeURIComponent(twitter);
	}
	return url;
    }

    function shareLink() {
	prompt("Copy to clipboard: Ctrl+C, Enter", document.getElementById("share-link").href);
	return false;
    }

    function contactContinue() {
	document.getElementById('setup2-box').style.display = 'none';
	document.getElementById('setup3-box').style.display = 'block';

	var email = document.getElementById('contact-email').value;
	var twitter = document.getElementById('contact-twitter').value;
	var link = getLink(passphrase, email, twitter);
	document.getElementById('link').href = link;
	document.getElementById('link').innerHTML = link;

	document.getElementById('share-link').href = link;
	document.getElementById('share-link').onclick = shareLink;

	document.getElementById('share-email').href = "mailto:?subject=My%20scrambl.is%20link&body=" + encodeURIComponent(link) + "%0A";
	document.getElementById('share-twitter').href = "https://twitter.com/intent/tweet?text=My%20scrambl.is%20link&url=" + encodeURIComponent(link);

	return false;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // Initial

    function selectWord() {
	var len = 58110;
	if (len !== words.length) {
	    return null;
	}
	while (true) {
	    var bytes = nacl.randomBytes(2);
	    var u16s = new Uint16Array(bytes.buffer, bytes.byteOffset);
	    var num = u16s[0];
	    if (num < len) {
		return words[num];
	    }
	}
    }

    function select7Words() {
	// TODO: could validate words? words must be 58110 in length
	// and each word must be alphabetically larger than the
	// previous
	return (selectWord() + " " + selectWord() + " " + selectWord() + " " + selectWord() + " " +
		selectWord() + " " + selectWord() + " " + selectWord());
    }

    function focusPassphraseConfirm() {
	document.getElementById('passphrase-confirm').focus();
    }


    ////////////////////////////////////////////////////////////////////////////////

    // Note, there should be either be a filled-in email and twitter
    // and no spare input boxes, or there should be one spare input
    // box.
    // Is this right? What if the link's contact details are all wrong?

    // the addressee should probably be below the input so we can click the button below.

    function getParams(str) {
	var params = [];
	var parts = str.split('&');
	for (var i = 0; i < parts.length; ++i) {
	    var kv = parts[i].split('=');
	    if (!kv || !kv.length || !kv[0]) {
		continue;
	    }
	    var key = decodeURIComponent(kv[0]);
	    var value = decodeURIComponent(kv.slice(1).join('='));
	    params.push({ key: key, value: value });
	}
	return params;
    }

    function paramsMapTakingLast(ps) {
	var map = {};
	for (var i = 0; i < ps.length; ++i) {
	    map[ps[i].key] = ps[i].value;
	}
	return map;
    }

    function loadEncryptToFromUrl() {
	var writeIndex = window.location.href.lastIndexOf('/write/');

	if (writeIndex >= 0) {
	    var paramsStart = window.location.href.indexOf('?', writeIndex);

	    if (paramsStart >= 0) {
		var params = paramsMapTakingLast(getParams(window.location.href.substring(paramsStart + 1)));
		var hasEmail = ('email' in params) && params['email'];
		var hasTwitter = ('twitter' in params) && params['twitter'];

		if (hasEmail || hasTwitter) {
		    if (hasEmail && hasTwitter) {

		    } else if (hasEmail) {

		    } else if (hasTwitter) {

		    }
		    return;
		}
	    }
	    // no twitter / email

	}
	// no key

    }

		var tweetIndex = window.location.href.indexOf('/tweet/', writeIndex + 7);
		var emailIndex = window.location.href.indexOf('/email/', writeIndex + 7);

		if (tweetIndex >= 0) {
		    var pubkey = window.location.href.substring(writeIndex + 7, tweetIndex);
		    var recipient = window.location.href.substring(tweetIndex + 7);
		} else if (emailIndex >= 0) {
		    var pubkey = window.location.href.substring(writeIndex + 7, emailIndex);
		    var recipient = window.location.href.substring(emailIndex + 7);
		} else {
		    var pubkey = window.location.href.substring(writeIndex + 7);
		    var recipient = null;
		}

		if (!isTaggedKeyValid(pubkey)) {
		    return false;
		}

		if (recipient) {
		    document.getElementById('recipient-in').value = decodeURIComponent(recipient);
		}
		document.getElementById('encrypt-to').value = pubkey;
		return true;
	    }
	}
	return false;
    }

    window.onload = function () {
	setTimeout(focusWrite, 0);

	loadEncryptToFromUrl();

	document.getElementById('all').style.display = 'block';
    };

    ////////////////////////////////////////////////////////////////////////////////

})();
