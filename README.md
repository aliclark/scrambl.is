scrambl.is
==========

scrambl.is is a small web page allowing the easy composition and
reading of encrypted messages, with usability as the primary goal.

Like miniLock, it uses TweetNaCL-JS and its public keys are shared in
base 58. However a passphrase will generate a different miniLock ID
and than its generated scrambl.is public key.

Own passphrases are not permitted - a 7 word passphrase of 50,000
potential words is generated using a 'Generate passphrase' button, and
an inputted passphrase must fit this definition for it to be used.

There is no scrypting or verification of entropy beyond this - a user
will be warned if they are inputting a bad passphrase, and it is up to
them to heed that warning if they require absolute privacy.

Like miniLock, scrambl.is employs a small checksum on the public key
to aid detection of mistypes, but this is reduced from 8 bits to 7
bits to ensure the resulting public keys have a maximum of 45
characters.

The page should work for any modern web browser and refers to no
external resources, so it can be easily downloaded for offline use. It
is up to the user decide appropriate precautions when using their web
browser, but if they wish to only view it in Google Chrome on an
offline computer, that option is available.

Very small messages of 44 characters or less will result in a
ciphertext of 128 characters, which can fit directly in a Twitter
direct message to a username of 9 characters or fewer.

Alternatively, the web page can retrieve ciphertext from its URL, so a
URL like the one below can be shared over Twitter with a much longer
message:

https://scrambl.is/read/OpSK8xu6xzuI8gaFMo7RpPVEWF6_0D3XUkA5GxyVQwlo6wOeidRxME4FY9kcDdu_R0xppK9yVcEmCdASzh1WAc5eZHeSy-1AlIIAFy4Ju3p9t6nHsIG8haw8l0RLEqbG

As in miniLock, it is up to the user to determine an appropriate
level of verification that the correct public key is being used for a
recipient.

For the vast majority of users, any mechanism of sharing the key will
be sufficiently secure. However if additional verification is required
then it is possible to do so, for example by meeting in person, or by
checking the key from several independent sources using a public
library computer.

scrambl.is will generate a link containing the user's public key and
optionally their twitter username or email address. This can be easily
shared with others when asking them to encrypt a message before
sending it. eg.

https://scrambl.is/write/2a1t2Z7hoSfmYTGPXFLVx4VmqUxhyXauZ8rDd4ZJt9Cr2/email/me@example.net

It is up to the user to widely advertise the correct public key or URL
for themselves and to help people they communicate with to find and
use the correct key, as appropriate.

Please open a Github issue if you see anything wrong. If you would
like to make the message private, please encrypt using the following
link:

https://scrambl.is/write/9aqfzCxGxoee4HzPBre9CUkJkrT3zHoGvRTcfXLLXAngw

Thanks, happy crypto-ing!
