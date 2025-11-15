### 关键说明
#### 1. 环境依赖
无需额外依赖，Python 3.6+ 内置库即可运行。

#### 2. FortiGate导入步骤
1. 登录FortiGate管理界面 → 安全 → IPS → 自定义规则 → 导入；
2. 选择生成的XML文件，点击“导入”，系统会自动校验规则格式；
3. 导入后需在IPS策略中启用“自定义规则”，并应用到对应的接口/策略。

#### 3. 支持与限制
- **支持的Snort字段**：action（alert/drop/pass）、proto（tcp/udp/icmp/ip）、IP/端口、content、pcre、sid、rev、msg；
- **不支持的Snort字段**：flow、threshold、reference、uricontent等（脚本会跳过这些选项，不影响核心检测逻辑）；
- **输入的Snort规则需符合标准语法（支持单行规则、注释行，不支持多行规则拆分）
- **FortiGate限制**：自定义IPS规则ID建议使用100000+（避免与系统规则冲突），规则名称长度不超过63字符（脚本自动截断）。
- **若遇到特殊字符（如中文、特殊符号）导致转换失败，可在命令行参数中给文件路径加引号（如Windows路径包含空格时）


### 使用方法（Windows/Linux/Mac）
#### 1. 基础使用（指定输入输出文件）
python snort2fortigate.py -i 你的Snort规则文件.rules -o 输出XML文件.xml

#### 2. 示例（实际场景）
# 简单转换（同目录下）
python snort2fortigate.py -i industrial_snort.rules -o fg_industrial_ips.xml

# 指定路径转换（Windows）
python snort2fortigate.py -i "C:\snort\rules\ot_rules.rules" -o "C:\fortigate\import\ot_ips.xml"

# 指定路径转换（Linux/Mac）
python snort2fortigate.py -i /home/user/snort/rules/ot_rules.rules -o /home/user/fortigate/ot_ips.xml

#### 3. 查看帮助

python snort2fortigate.py -h

会显示详细的参数说明和使用示例：

usage: snort2fortigate.py [-h] -i INPUT -o OUTPUT

Snort IPS规则转FortiGate自定义IPS规则工具

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        输入Snort规则文件路径（必填），如：snort_rules.rules
  -o OUTPUT, --output OUTPUT
                        输出FortiGate XML文件路径（必填），如：fortigate_ips.xml

示例：python snort2fortigate.py -i snort_rules.rules -o fortigate_ips.xml

### 示例转换效果
Snort 原始规则：
alert tcp any any -> any 80 (msg:"HTTP Exploit Attempt"; content:"/exploit.php"; sid:1000001; rev:2; offset:0; depth:20;)

转换后的 FortiGate XML 规则：
xml
<ips version="1.0">
  <rule id="1000001" name="SNORT_1000001_HTTP Exploit Attempt" action="alert" status="enable" log="enable">
    <protocol>tcp</protocol>
    <src-ip>0.0.0.0/0</src-ip>
    <src-port>0-65535</src-port>
    <dst-ip>0.0.0.0/0</dst-ip>
    <dst-port>80-80</dst-port>
    <signature type="pattern">
      <pattern id="1" value="/exploit.php" offset="0" depth="20"/>
    </signature>
    <comment>Snort SID: 1000001, Rev: 2, Original Msg: HTTP Exploit Attempt</comment>
  </rule>
</ips>

