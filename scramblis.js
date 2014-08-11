
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

    var lenientB64LineRegex = /^[ \-\_\+\/a-zA-Z0-9]*$/;

    // may be overly harsh to not allow other line lengths than multiples of 64?
    function isLenientB64(x) {
	var lines = x.split(/\s+/g);
	for (var i = 0; i < lines.length; ++i) {
	    var line = lines[i];
	    if ((line.length % 64) !== 0) {
		return false;
	    }
	    if (line && !lenientB64LineRegex.test(line)) {
		return false;
	    }
	}
	return true;
    }

    var b58Regex = /^[1-9A-HJ-NP-Za-km-z]*$/;
    function isB58(x) {
	return b58Regex.test(x);
    }

    function getValidPubkeyB58(x) {
	if (!x || ((x.length < 33) || (x.length > 45))) {
	    return null;
	}
	if (!isB58(x)) {
	    return null;
	}
	var bytes = dB58(x);
	if (bytes.byteLength !== (nacl.box.publicKeyLength + 1)) {
	    return null;
	}
	var keyPart = bytes.subarray(1, 1 + nacl.box.publicKeyLength);
	if ((nacl.hash(keyPart)[0] & 127) !== bytes[0]) {
	    return null;
	}
	return keyPart;
    }

    function isTaggedKeyValid(x) {
	return !!getValidPubkeyB58(x);
    }
    
    ////////////////////////////////////////////////////////////////////////////////

    function stripWhitespaceEnds(x) {
	x = x.replace(/^\s+/, '');
	x = x.replace(/\s+$/, '');
	return x;
    }

    function stripWhitespace(x) {
	x = x.replace(/\s+/g, '');
	return x;
    }

    function stdB64Chars(x) {
	x = x.replace(/\_/g, '/');
	x = x.replace(/\-/g, '+');
	return x;
    }

    function dB64(x) {
	x = stripWhitespace(x);
	x = stdB64Chars(x);
	try {
	    return nacl.util.decodeBase64(x);
	} catch (e) {
	    console.log(e.message);
	    return null;
	}
    }

    function urlSafeB64(x) {
	x = x.replace(/\//g, '_');
	x = x.replace(/\+/g, '-');
	return x;
    }

    function eB64(b) {
	var x = nacl.util.encodeBase64(b);
	return x;
    }

    function dB58(x) {
	return Base58.decode(x);
    }

    function eB58(b) {
	return Base58.encode(b);
    }

    function taggedB58Key(b) {
	var tagged = new Uint8Array(nacl.box.publicKeyLength + 1);
	tagged.set(b, 1);
	tagged[0] = nacl.hash(b)[0] & 127;
	return eB58(tagged);
    }

    ////////////////////////////////////////////////////////////////////////////////

    function padArray(msg) {
	// also count the pubkey and auth size, 4 bytes for length
	var overhead = 32 + 16 + 4;
	var totalLen = msg.byteLength + overhead;
	// I like 48 because it b64s to 64chars which is a good line size
	var initial = 48;
	while (initial < totalLen) {
	    initial *= 2;
	}
	var space = initial - totalLen;
	var backing = new ArrayBuffer(4 + msg.byteLength + space);
	var u32s = new Uint32Array(backing);
	u32s[0] = msg.byteLength;
	var padded = new Uint8Array(backing);
	padded.set(msg, 4);
	return padded;
    }

    // auth check shouldn't have passed if we got this far but may as
    // well check for errors.
    function unpadArray(msg) {
	if (msg.byteLength < 4) {
	    return null;
	}
	var u32s = new Uint32Array(msg.buffer, msg.byteOffset);
	var actualLen = u32s[0];
	if (msg.byteLength < (4 + actualLen)) {
	    return null;
	}
	return msg.subarray(4, 4 + actualLen);
    }

    ////////////////////////////////////////////////////////////////////////////////

    function scrabblis_en_box(plain, publicKey) {
	var nonce = new Uint8Array(nacl.box.nonceLength);
	var keyPair = nacl.box.keyPair();

	try {
	    var msg = nacl.util.decodeUTF8(plain);
	} catch (e) {
	    return null;
	}

	var padded = padArray(msg);

	var box = nacl.box(padded, nonce, publicKey, keyPair.secretKey);

	var bin = new Uint8Array(nacl.box.publicKeyLength + box.byteLength);
	bin.set(keyPair.publicKey);
	bin.set(box, nacl.box.publicKeyLength);

	var b64 = '';
	for (var i = 0; i < bin.length; i += 48) {
	    b64 += eB64(bin.subarray(i, i+48)) + '\n';
	}

	return b64;
    }

    function scrabblis_de_box(b64, secretKey) {
	var nonce = new Uint8Array(nacl.box.nonceLength);
	var bin = dB64(b64);
	if (!bin) {
	    return null;
	}
	var publicKey = bin.subarray(0, nacl.box.publicKeyLength);
	var box = bin.subarray(nacl.box.publicKeyLength);
	try {
	    var padded = nacl.box.open(box, nonce, publicKey, secretKey);
	    if (!padded) {
		return null;
	    }
	} catch (e) {
	    console.log(e.message);
	    return null;
	}
	var msg = unpadArray(padded);
	if (!msg) {
	    return null;
	}
	try {
	    return nacl.util.encodeUTF8(msg);
	} catch (e) {
	    console.log(e.message);
	    return null;
	}
    }

    ////////////////////////////////////////////////////////////////////////////////

    function loadCiphertextFromUrl() {
	var readIndex = window.location.href.lastIndexOf('/read/');
	if (readIndex > 0) {
	    var ciphertext = window.location.href.substring(readIndex + 6);
	    if (!ciphertext || !isLenientB64(ciphertext)) {
		return false;
	    }
	    var el = document.getElementById('decrypt-in');
	    el.value = '';
	    for (var i = 0; i < ciphertext.length; i += 64) {
		el.value += ciphertext.substring(i, i+64) + '\n';
	    }
	    return true;
	}
	return false;
    }

    function loadEncryptToFromUrl() {
	var writeIndex = window.location.href.lastIndexOf('/write/');
	if (writeIndex >= 0) {
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
	return false;
    }

    ////////////////////////////////////////////////////////////////////////////////

    function copyLink() {
	prompt("Copy to clipboard: Ctrl+C, Enter", document.getElementById("encrypt-out-link").href);
	return false;
    }

    function copyShareLink() {
	prompt("Copy to clipboard: Ctrl+C, Enter", document.getElementById("share-link").href);
	return false;
    }

    ////////////////////////////////////////////////////////////////////////////////

    function recipientType(val) {
	return (val.indexOf('@') > 0) ? 'email' : 'tweet';
    }

    function recipientChange(ciphertext) {
	var val = document.getElementById('recipient-in').value;
	var tweet = document.getElementById('tweet-btn');
	var email = document.getElementById('email-btn');

	if (!ciphertext) {
	    ciphertext = document.getElementById('encrypt-out').textContent;
	}

	if (!val || !ciphertext || !stripWhitespace(ciphertext)) {
	    tweet.style.display = 'none';
	    email.style.display = 'none';
	    return;
	}

	switch (recipientType(val)) {
	case 'email':
	    if (ciphertext) {
		email.href = "mailto:" + encodeURIComponent(val) + "?body=" + encodeURIComponent(stdB64Chars(ciphertext));
	    }
	    tweet.style.display = 'none';
	    email.style.display = 'inline';
	    break;
	case 'tweet':
	    var to = val.indexOf('@') === 0 ? val.substring(1) : val;
	    if (ciphertext) {
		tweet.href = "https://twitter.com/intent/tweet?text=d%20" + encodeURIComponent(to) + "&url=https%3A%2F%2Fscrambl.is%2Fread%2F" + stripWhitespace(urlSafeB64(ciphertext));
	    }
	    tweet.style.display = 'inline';
	    email.style.display = 'none';
	    break;
	}
    }

    function recipientChangeEvent() {
	recipientChange();
    }

    ////////////////////////////////////////////////////////////////////////////////

    function hasClass(el, name) {
	return new RegExp('(\\s|^)'+name+'(\\s|$)').test(el.className);
    }

    function addClass(el, name) {
	if (!hasClass(el, name)) { el.className += (el.className ? ' ' : '') +name; }
    }

    function removeClass(el, name) {
	if (hasClass(el, name)) {
	    el.className=el.className.replace(new RegExp('(\\s|^)'+name+'(\\s|$)'),' ').replace(/^\s+|\s+$/g, '');
	}
    }

    function hasStuff(el) {
	addClass(el, 'hasStuff');
    }

    function doesntHaveStuff(el) {
	removeClass(el, 'hasStuff');
    }

    ////////////////////////////////////////////////////////////////////////////////

    var prevTo = null;
    var prevIn = null;
    var prevOut = null;

    function enBoxValue() {
	var encryptTo = document.getElementById('encrypt-to').value;
	var inv = document.getElementById('encrypt-in').value;
	if ((encryptTo === prevTo) && (inv === prevIn)) {
	    return prevOut;
	}
	// copy-pasting could have added some space
	encryptTo = stripWhitespaceEnds(encryptTo);
	// update the form value with stripped space
	document.getElementById('encrypt-to').value = encryptTo;

	var pubkey = getValidPubkeyB58(encryptTo)
	if (!pubkey) {
	    return null;
	}
	if (inv === '') {
	    return null;
	}
	var boxed = scrabblis_en_box(inv, pubkey);
	if (boxed) {
	    prevTo = encryptTo;
	    prevIn = inv;
	    prevOut = boxed;
	}
	return boxed;
    }

    function enBox() {
	var boxed = enBoxValue();

	if (boxed === null) {
	    document.getElementById('encrypt-out').textContent = "\n\n";
	    doesntHaveStuff(document.getElementById('encrypt-out-cont'));
	    document.getElementById('encrypt-out-link').style.display = 'none';
	} else {
	    document.getElementById('encrypt-out').textContent = boxed;
	    hasStuff(document.getElementById('encrypt-out-cont'));
	    document.getElementById('encrypt-out-link').href = "https://scrambl.is/read/" + stripWhitespace(urlSafeB64(boxed));
	    document.getElementById('encrypt-out-link').style.display = 'block';
	}
	recipientChange(boxed);
    }

    ////////////////////////////////////////////////////////////////////////////////

    function deBoxer(secretKey) {
	return function () {
	    var toDecrypt = document.getElementById('decrypt-in').value;
	    toDecrypt = stripWhitespaceEnds(toDecrypt);
	    if (toDecrypt.indexOf("https://scrambl.is/read/") === 0) {
		toDecrypt = toDecrypt.substring("https://scrambl.is/read/".length);
	    }
	    if (toDecrypt && isLenientB64(toDecrypt)) {
		var deboxed = scrabblis_de_box(toDecrypt, secretKey);
	    } else {
		var deboxed = null;
	    }
	    if (deboxed === null) {
		document.getElementById('decrypt-out').textContent = "\n\n";
		doesntHaveStuff(document.getElementById('decrypt-out-cont'));
	    } else {
		document.getElementById('decrypt-out').textContent = deboxed;
		hasStuff(document.getElementById('decrypt-out-cont'));
		var lines = deboxed.split('\n').length - 1;
		if (lines === 0) {
		    document.getElementById('decrypt-out').textContent += '\n\n';
		} else if (lines === 1) {
		    document.getElementById('decrypt-out').textContent += '\n';
		}
	    }
	};
    }

    ////////////////////////////////////////////////////////////////////////////////

    function setupHide() {
	document.getElementById('passphrase-shown').textContent = '';
	document.getElementById('setup-box').style.display = 'none';
	document.getElementById('passphrase-in').focus();
    }

    ////////////////////////////////////////////////////////////////////////////////

    function stopPropagation(evt) {
	if (typeof evt.stopPropagation != "undefined") {
            evt.stopPropagation();
	} else {
            evt.cancelBubble = true;
	}
    }

    // No entropy detection, so "it it it it it it it" would
    // pass.
    function isProperPassphrase(x) {
	var parts = x.split(' ');
	var wordsFound = 0;
	for (var i = 0; i < parts.length; ++i) {
	    if (words.indexOf(stripWhitespace(parts[i])) >= 0) {
		wordsFound += 1;
	    }
	}
	return wordsFound >= 7;
    }

    // A form exists to enable the Remember Password feature of Firefox
    // (unfortunately other browsers won't even remember with that).  But
    // it's quite important to kill the event so it doesn't actually post
    // to the server.

    function reKey(evt) {
	evt = evt || window.event; // For IE
	stopPropagation(evt);
	evt.preventDefault();

	var passphrase = document.getElementById('passphrase-in').value;
	document.getElementById('passphrase-in').value = '';

	if (!isProperPassphrase(passphrase)) {
	    alert('Please use one of the passphrases made with the Generate passphrase button.\n\nYou may also be receiving this message if you mistyped one of those passphrases.');
	    return false;
	}

	document.getElementById('passphrase-in').style.visibility = 'hidden';
	document.getElementById('passphrase-use').style.visibility = 'hidden';

	var keyPair = nacl.box.keyPair.fromSecretKey(nacl.hash(nacl.util.decodeUTF8(passphrase)).subarray(0, nacl.box.secretKeyLength));
	document.getElementById('mykey').textContent = taggedB58Key(keyPair.publicKey);

	var deBox = deBoxer(keyPair.secretKey);
	document.getElementById('decrypt-in').onchange = deBox;
	document.getElementById('decrypt-in').onkeyup = deBox;
	deBox();

	setupHide();

	var url = 'https://scrambl.is/write/' + taggedB58Key(keyPair.publicKey);
	var address = document.getElementById('address-in').value;
	if (address) {
	    switch (recipientType(address)) {
	    case 'email':
		url += '/email/' + encodeURIComponent(address).replace(/%40/g, '@');;
		break;
	    case 'tweet':
		url += '/tweet/' + encodeURIComponent(address);
		break;
	    }
	}
	document.getElementById('share-link').href = url;
	document.getElementById('share-email').href = "mailto:?body=" + encodeURIComponent(url);
	document.getElementById('share-twitter').href = "https://twitter.com/intent/tweet?text=My%20scrambl.is%20link&url=" + encodeURIComponent(url);

	document.getElementById('your-address-cont').style.display = 'none';
	document.getElementById('passphrase-in-cont').style.display = 'none';
	document.getElementById('your-key-cont').style.display = 'block';

	document.getElementById('share-link').focus();
	return false;
    }

    ////////////////////////////////////////////////////////////////////////////////

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

    function generateKey() {
	document.getElementById('passphrase-generate').style.display = 'none';
	document.getElementById('passphrase-showing-box').style.display = 'block';
	document.getElementById('passphrase-shown').textContent = select7Words();
	document.getElementById('passphrase-in').focus();
	return false;
    }

    ////////////////////////////////////////////////////////////////////////////////

    function focusGeneratePassphrase() {
	document.getElementById('passphrase-generate').focus();
    }

    function focusEncryptIn() {
	document.getElementById('encrypt-in').focus();
    }

    function focusPassphraseIn() {
	document.getElementById('passphrase-in').focus();
    }

    ////////////////////////////////////////////////////////////////////////////////

    window.onload = function () {

	var hasRandom = false;
	try {
	    nacl.randomBytes(1);
	    hasRandom = true;
	} catch (e) {
	    
	}

	// TODO: local-storage for recipient->pubkey mapping?
	// -- less important with the shareable links
	// -- watch out for /write/ links containing false keys.

	// TODO: allow Upload file button and check file magic to
	// offer file download on return. Or eg. reserve max padding
	// size to mean eg. "is multipart email" and try to parse
	// multipart stuff.

	// TODO: If loading from URL, just show that component? maybe
	// with a link to a fresh page?

	// TODO: Could have a button to upload ciphertext to server
	// and provide a short URL like
	// https://scrambl.is/read/SYjjjGRPa4zOCjw3SUlJ but would
	// require development time for implementation and DOS
	// protection. A link expiry of 1 week would help, but needs
	// to be clear that is the case.

	var loadedText = loadCiphertextFromUrl();

	if (hasRandom) {
	    var loadedKey = loadEncryptToFromUrl();

	    document.getElementById('passphrase-generate').onclick = generateKey;

	    document.getElementById('encrypt-in').onchange = enBox;
	    document.getElementById('encrypt-to').onchange = enBox;
	    document.getElementById('encrypt-in').onkeyup = enBox;
	    document.getElementById('encrypt-to').onkeyup = enBox;

	    document.getElementById('recipient-in').onchange = recipientChangeEvent;
	    document.getElementById('recipient-in').onkeyup = recipientChangeEvent;

	    recipientChange();

	    document.getElementById('encrypt-out-link').onclick = copyLink;
	    document.getElementById('share-link').onclick = copyShareLink;

	    enBox();

	} else {
	    var loadedKey = false;

	    document.getElementById('write-form').style.display = 'none';
	    document.getElementById('setup-form').style.display = 'none';

	    document.getElementById('write-no-random').style.display = 'block';
	    document.getElementById('setup-no-random').style.display = 'block';
	}

	document.getElementById('passphrase-use').onclick = reKey;

	if (loadedText) {
	    setTimeout(focusPassphraseIn, 0);
	} else if (loadedKey) {
	    setTimeout(focusEncryptIn, 0);
	} else {
	    setTimeout(focusGeneratePassphrase, 0);
	}
	document.getElementById('all').style.display = 'block';
    };

    ////////////////////////////////////////////////////////////////////////////////

})();
