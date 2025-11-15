import re
import xml.etree.ElementTree as ET
from xml.dom import minidom
import argparse
import os

class SnortToFortiGateIPSConverter:
    def __init__(self):
        self.action_map = {
            "alert": "alert",
            "drop": "block",
            "pass": "allow",
            "log": "alert"
        }
        self.default_rule_id_start = 100000
        self.current_rule_id = self.default_rule_id_start

    def _parse_snort_rule(self, line):
        """解析单条Snort规则,提取核心字段"""
        rule = {
            "action": None,
            "proto": None,
            "src_ip": "0.0.0.0/0",
            "src_port": "0-65535",
            "dst_ip": "0.0.0.0/0",
            "dst_port": "0-65535",
            "content": [],
            "pcre": [],
            "sid": None,
            "rev": "1",
            "msg": "Snort Imported Rule",
            "options": {}
        }

        line = re.sub(r'#.*$', '', line.strip())
        if not line:
            return None

        head_match = re.match(r'^(\w+)\s+(\w+)\s+([^\s]+)\s+([^\s]+)\s+->\s+([^\s]+)\s+([^\s]+)\s*(.*)$', line)
        if not head_match:
            print(f"警告:无法解析规则头部 - {line}")
            return None

        rule["action"] = head_match.group(1).lower()
        rule["proto"] = head_match.group(2).lower()
        src_ip = head_match.group(3)
        src_port = head_match.group(4)
        dst_ip = head_match.group(5)
        dst_port = head_match.group(6)
        options_part = head_match.group(7)

        rule["src_ip"] = self._convert_ip(src_ip)
        rule["dst_ip"] = self._convert_ip(dst_ip)
        rule["src_port"] = self._convert_port(src_port)
        rule["dst_port"] = self._convert_port(dst_port)

        if options_part:
            options = re.findall(r'(\w+):(?:"([^"]+)"|([^\s;]+))(?:;|$)', options_part)
            for opt_key, opt_val_quoted, opt_val in options:
                val = opt_val_quoted if opt_val_quoted else opt_val
                if opt_key == "sid":
                    rule["sid"] = val
                elif opt_key == "rev":
                    rule["rev"] = val
                elif opt_key == "msg":
                    rule["msg"] = val
                elif opt_key == "content":
                    rule["content"].append(val)
                elif opt_key == "pcre":
                    rule["pcre"].append(val)
                else:
                    rule["options"][opt_key] = val

        if rule["action"] not in self.action_map:
            print(f"警告:不支持的Snort动作 - {rule['action']}，规则跳过")
            return None
        if rule["proto"] not in ["tcp", "udp", "icmp", "ip"]:
            print(f"警告:不支持的协议 - {rule['proto']}，规则跳过")
            return None

        if rule["sid"] and rule["sid"].isdigit():
            rule["fg_rule_id"] = int(rule["sid"])
            if rule["fg_rule_id"] < 100000:
                rule["fg_rule_id"] += self.default_rule_id_start
        else:
            rule["fg_rule_id"] = self.current_rule_id
            self.current_rule_id += 1

        return rule

    def _convert_ip(self, snort_ip):
        """IP格式转换"""
        if snort_ip == "any":
            return "0.0.0.0/0"
        if "/" not in snort_ip:
            return f"{snort_ip}/32"
        return snort_ip

    def _convert_port(self, snort_port):
        """端口格式转换"""
        if snort_port == "any":
            return "0-65535"
        if ":" in snort_port:
            return snort_port.replace(":", "-")
        if snort_port.isdigit():
            return f"{snort_port}-{snort_port}"
        return snort_port

    def _build_fg_xml(self, rules):
        """构建FortiGate XML规则"""
        root = ET.Element("ips")
        root.set("version", "1.0")

        for rule in rules:
            if not rule:
                continue

            rule_elem = ET.SubElement(root, "rule")
            rule_elem.set("id", str(rule["fg_rule_id"]))
            rule_name = f"SNORT_{rule['fg_rule_id']}_{rule['msg'][:30]}".replace(' ', '_')
            rule_elem.set("name", rule_name)
            rule_elem.set("action", self.action_map[rule["action"]])
            rule_elem.set("status", "enable")
            rule_elem.set("log", "enable")

            ET.SubElement(rule_elem, "protocol").text = rule["proto"]
            ET.SubElement(rule_elem, "src-ip").text = rule["src_ip"]
            ET.SubElement(rule_elem, "src-port").text = rule["src_port"]
            ET.SubElement(rule_elem, "dst-ip").text = rule["dst_ip"]
            ET.SubElement(rule_elem, "dst-port").text = rule["dst_port"]

            sig_elem = ET.SubElement(rule_elem, "signature")
            sig_elem.set("type", "pattern")

            for idx, content in enumerate(rule["content"]):
                pattern_elem = ET.SubElement(sig_elem, "pattern")
                pattern_elem.set("id", str(idx + 1))
                pattern_elem.set("value", content)
                if "offset" in rule["options"]:
                    pattern_elem.set("offset", rule["options"]["offset"])
                if "depth" in rule["options"]:
                    pattern_elem.set("depth", rule["options"]["depth"])

            for idx, pcre in enumerate(rule["pcre"]):
                pcre_elem = ET.SubElement(sig_elem, "pcre")
                pcre_elem.set("id", str(idx + 1))
                pcre_elem.text = pcre

            comment_elem = ET.SubElement(rule_elem, "comment")
            comment_elem.text = f"Snort SID: {rule['sid'] if rule['sid'] else 'N/A'}, Rev: {rule['rev']}, Original Msg: {rule['msg']}"

        xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
        return "\n".join([line for line in xml_str.split("\n") if line.strip()])

    def convert(self, snort_file_path, fg_output_path):
        """主转换函数"""
        # 校验输入文件是否存在
        if not os.path.exists(snort_file_path):
            raise FileNotFoundError(f"输入文件不存在：{snort_file_path}")
        
        # 读取Snort规则
        snort_rules = []
        with open(snort_file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                try:
                    parsed_rule = self._parse_snort_rule(line)
                    if parsed_rule:
                        snort_rules.append(parsed_rule)
                except Exception as e:
                    print(f"错误:解析第{line_num}行规则失败 - {str(e)},规则跳过")

        if not snort_rules:
            print("警告:未解析到有效Snort规则,无输出文件生成")
            return

        # 生成XML并写入文件
        fg_xml = self._build_fg_xml(snort_rules)
        # 确保输出目录存在
        output_dir = os.path.dirname(fg_output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        with open(fg_output_path, "w", encoding="utf-8") as f:
            f.write(fg_xml)

        print(f"转换完成！")
        print(f"输入文件：{snort_file_path}")
        print(f"输出文件：{fg_output_path}")
        print(f"处理统计：共解析 {len(snort_rules)} 条有效规则")

def main():
    # 解析命令行参数
    parser = argparse.ArgumentParser(
        description="Snort IPS规则转FortiGate自定义IPS规则工具",
        epilog="示例:python snort2fortigate.py -i snort_rules.rules -o fortigate_ips.xml"
    )
    parser.add_argument(
        "-i", "--input", 
        required=True, 
        help="输入Snort规则文件路径(必填),如:snort_rules.rules"
    )
    parser.add_argument(
        "-o", "--output", 
        required=True, 
        help="输出FortiGate XML文件路径(必填),如:fortigate_ips.xml"
    )
    args = parser.parse_args()

    # 执行转换
    try:
        converter = SnortToFortiGateIPSConverter()
        converter.convert(args.input, args.output)
    except Exception as e:
        print(f"转换失败：{str(e)}")
        exit(1)

if __name__ == "__main__":
    main()