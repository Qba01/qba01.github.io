---
title: DBatLoader - Malware Analysis Walkthrough
date: 2025-07-17
tags:
  - malware
  - DBatLoader
  - JS
  - DHL
status:
  - In-progress
link:
---

> This is my "first" report/summary/walkthrough post, it's very rough unpolished and with comments/notes of what I noted while I was working on the file. Still I wanted to post it so I can show snippet of what I'm doing aaand hopefully soon enough I will finish this analysis and report.
{: .prompt-info }

### Threat Overview
- **Threat Name**: DBatLoader
- Type Format: #JS
- Hash Values: 
	- SHA256: e418cbad6006696595a396905ac73ca85eb369ca4ea3afe04619ee88468aeb50
- **Observations**
  - Behavior: [Actions performed by the malware]
  - C2 Communication: [Details about command and control servers]
  - Persistence Mechanisms: [How the threat maintains its presence]
- **Attack Vector**:
  - Entry Point: [How the threat gains access, e.g., email, compromised website]
  - Exploited Vulnerabilities: [Specific vulnerabilities exploited]
- **Indicators of Compromise (IoCs)**: [List of IoCs, e.g., file hashes, malicious IPs]

### Walkthrough
First of the bat, there is this annoying obfuscation. I saw similar example earlier in different malicious file I was dissecting but I wanted to use it to make an this report/walkthrough thingy, I got stuck and didn't have much time for the whole thing so I skipped it. And well here we are, now I'm not leaving it like this.
So the unreadable blob might be useless or it's like this on purpose and can't be change for the malware to run as the author intended. The values in rounded brackets are probably coordinates of instruction to be read so the code compiles correctly.
![[Pasted image 20250721140043.png]]

The beginning is a slow tidius task, which is what the authors want. 
But so far there are few functions and variables which seem important and it's a good start. And here is a snippet of them copied and reorganized form the original file.
```js
function _0x3e2d(_0x5e7335,_0x54caa2){var _0x1091ef=_0x1091();return _0x3e2d=function(_0x3e2d60,_0x460ec8){_0x3e2d60=_0x3e2d60-0x109;var _0x1917f6=_0x1091ef[_0x3e2d60];return _0x1917f6;},_0x3e2d(_0x5e7335,_0x54caa2);
catch(_0x24b111){_0x3c57a9[_0x5a110b(0x10d)](_0x3c57a9[_0x5a110b(0x128)]());}}}(_0x3413,0xe300e));
var _0x358738=_0x3413();return _0x4813=function(_0x5be425,_0x573a49){_0x5be425=_0x5be425-0xe8;var _0x5774e3=_0x358738[_0x5be425];return _0x5774e3;

function _0x3413(){var _0x5b81b3=_0x3e2d,_0x39473b=[_0x5b81b3(0x109),_0x5b81b3(0x122),_0x5b81b3(0x140),_0x5b81b3(0x14e),'/^(http(s)?:\x5c/\x5c/)?',_0x5b81b3(0x11d),_0x5b81b3(0x11c),_0x5b81b3(0x143),_0x5b81b3(0x12d),_0x5b81b3(0x137),_0x5b81b3(0x125),_0x5b81b3(0x148),_0x5b81b3(0x115),_0x5b81b3(0x13a),_0x5b81b3(0x123),_0x5b81b3(0x14a),_0x5b81b3(0x10f),_0x5b81b3(0x135),_0x5b81b3(0x11a),_0x5b81b3(0x114),_0x5b81b3(0x13b),_0x5b81b3(0x150),'host',_0x5b81b3(0x11f),_0x5b81b3(0x116),'src',_0x5b81b3(0x149),'attachEvent',_0x5b81b3(0x151),_0x5b81b3(0x10b)
```

After figuring out which variables and fuctions are important they can be swapped for easier to read or even simplified. All of this is just another way of making analysts life harder and function ABC is often evoking itself.
`_0x3413` is an function which returns the main array `_0x39473b` with all of the obfuscated commands. I will rename it too `func1` because I'm creative
`_0x39473b` is an array so now it will be known as `array1`
`_0x358738` just calls `_0x3413()` basically, lets name it `var3`
`var _0x5b81b3=_0x3e2d` and `_0x3e2d` is the first declared function if I didn't miss any other so maybe `funcFirst`. Also we don't need `_0x5b81b3`. But I will keep it for a while just in case if I mess something up.
`var _0x5774e3=_0x358738[_0x5be425]` as `var1` also it appears only twice so it's also not important, it's just an obfuscation.
`_0x5be425` is `var2`, buuut can't just replace all of that because it's also used as a number or some value `_0x5be425=_0x5be425-0xe8`.
I found `_0x4813` 6 matches for this string, but only half of that it's important, when it's used as name for a function, `func3`
`_0x5b81b3` is `varFunc` now


```
_0x3e2d - 7 ale tylko 5 ważnych
_0x4813 - 6 ale tylko 4 ważne
_0x3413 - 5 ale tylko 4 ważne
_0x5b81b3 - 49/49
_0x4721 - 4/5
_0x3fcb - 89 but only last 3 
_0x81cfae - 52/52
_0x3ee5e0 - 2/2
_0x25cb6a - 2/2
_0x7d116e - 2/2
_0x5a2079 - 4/4
_0x2cea4d - 2/2
_0x3578b9 - 1/1
_0x39473b - 2/2
_0x1091
```

I had to go back and start from beginning because of new ideas how to aproach this. `⭴ſᕨ⒨આዃੀĎ⋆ସ⭴ſᕨ⒨` does a good job in prolonging the analysis, after a while I decided to remove it manually from the file, which decreased the size of a file from around 6.989KB to 1.022KB. I had default settings still in SublimeText which I'm using to analyze it, and I caught myself removing too large chunks which hid just a few variables without which the code wouldn't compile. I decided to replace those chunks with some placeholder names. However now after removing those parts the code is indistinguasable, It just looks like a wall of text.


















```
_0x3e2d -> firstFunc (return 2 values)
_0x4813 -> func2
_0x4721 -> func3
_0x3413 -> func4
_0x1091 -> func5
_0x3fcb -> func6



_0x1091ef -> varF5
```


firstFunc -> uses func5()

func2 -> uses func4()

func3 -> uses firstFunc and func2 

func4 -> uses firstFunc

func5 -> just holds cutted commands

func6 -> uses func3()


|           | firstFunc | func2 | func3 | func4 | func5 | func6 |
| --------- | --------- | ----- | ----- | ----- | ----- | ----- |
| firstFunc |           |       |       |       | X     |       |
| func2     |           |       |       | X     |       |       |
| func3     | X         | X     |       |       |       |       |
| func4     | X         |       |       |       |       |       |
| func5     |           |       |       |       |       |       |
| func6     |           |       | X     |       |       |       |



okay i was tinkering around for too long. 


Order of executing the code:
1. firstFunc declared (uses func5)
2. func2 declared (uses func4)
3. func3 declared (uses firstFunc and func2)
4. func4 declared (uses firstFunc)
5. func5 declared
6. func6 declared (uses func3)

What methods are used by the JS code?
shift() - `The `shift()` method in JavaScript removes the first element from an array and returns that element, while also changing the length of the array.`
replace() - replaces matched pattern
FileExists? -
length() - returns length of target array
Type
location.host? - `The `location.host` property returns the host (IP adress or domain) and port of a URL. The `location.host` property can also be set, to navigate to the same URL with a new host and port.`
event - its related to HTML events, as in this example on specific mouse interations
src - `The `src` attribute specifies the URL of an external script file.`
modo ??
mousedown
mouseout
split() - similarly to replace(), it divides strings into array of substrings, so maybe the removed strings are important
href

text

protocol

`આዃੀĎ⋆ସ⭴ſᕨ⒨`
E? `E[_0x138f04(0x21b)]=huyttara;`

### Summary
## Revision History
- **2025-07-17**: Initial threat acquisition and research.
- **2025-09-05**: Posting draft version of post.
<!-- - **2025-07-17**: Updated with detailed technical analysis and impact assessment.
- **2025-07-17**: Final review and development of response strategies. -->
