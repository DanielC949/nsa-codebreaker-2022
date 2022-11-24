# Task B1

## Background
> The attacker left a file with a ransom demand, which points to a site where they're demanding payment to release the victim's files.
>
> We suspect that the attacker may not have been acting entirely on their own. There may be a connection between the attacker and a larger ransomware-as-a-service ring.
>
> Analyze the demand site, and see if you can find a connection to another ransomware-related site.
> ### Downloads
> Demand note from the attacker (`YOUR_FILES_ARE_SAFE.txt`)
> ### Prompt
> Enter the domain name for the associated site

## Writeup
**TL;DR**: ~~Just read the paragraph~~ Use the network inspector in your favorite browser's dev tools to view requests made by the site given in the demand note.

The demand note gives a URL to go to, and when opening that site, we see a standard ransom note with a timer for how long until the key is deleted. Since we're looking for a connection to another ransomware-related site, we can simply look at the network requests made by this site. Doing that, we see a request to `https://xekflqhmhrsoelot.ransommethis.net/demand?cid=89184`, which looks like what we're looking for. Entering the domain name into the answer box, we get our task B1 badge!