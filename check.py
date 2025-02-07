#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import json
import logging
import datetime
import platform
import xml.etree.ElementTree as ET  # nmap XML 결과 파싱을 위한 모듈

# 로그 설정: 보안 점검 시 발생하는 이벤트를 파일에 기록합니다.
logging.basicConfig(
    level=logging.INFO,                        # 로그 레벨: INFO 이상의 메시지만 기록
    filename="security_check.log",             # 로그 파일 이름
    format="%(asctime)s - %(levelname)s - %(message)s",  # 로그 메시지 형식
    datefmt="%Y-%m-%d %H:%M:%S"                 # 날짜 및 시간 형식
)

def check_os_version():
    """
    운영체제 점검 함수:
    - platform 모듈을 사용하여 현재 시스템의 운영체제 정보를 수집합니다.
    - 수집된 정보는 딕셔너리 형태로 반환합니다.
    """
    try:
        os_info = {
            "OS 이름": platform.system(),        # 예: 'Linux', 'Windows', 'Darwin'
            "OS 버전": platform.version(),        # 운영체제 상세 버전 정보
            "릴리즈": platform.release(),         # 릴리즈 정보
            "플랫폼": platform.platform(),        # 종합 운영체제 정보
            "아키텍처": platform.machine()        # 시스템 아키텍처 (예: 'x86_64')
        }
        logging.info("운영체제 점검 성공: %s", os_info)
        return {"status": "success", "data": os_info}
    except Exception as e:
        logging.error("운영체제 점검 실패: %s", str(e))
        return {"status": "error", "error": str(e)}

def check_ports_nmap():
    """
    nmap을 사용하여 열려있는 포트와 해당 서비스의 버전 정보를 수집하는 함수:
    - nmap 명령어: "nmap -sV -oX - localhost"
      → -sV : 서비스 버전 탐지 옵션
      → -oX - : XML 형식으로 출력(표준 출력)
    - XML 형식의 결과를 파싱하여 각 포트의 서비스 이름 및 버전 정보를 추출합니다.
    """
    try:
        cmd = ["nmap", "-sV", "-oX", "-", "localhost"]
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True)
        root = ET.fromstring(result)
        port_service_mapping = {}
        for host in root.findall('host'):
            ports = host.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    port_id = port.get('portid')        # 포트 번호
                    protocol = port.get('protocol')       # 프로토콜 (tcp, udp 등)
                    state_elem = port.find('state')
                    if state_elem is not None and state_elem.get('state') == "open":
                        service_elem = port.find('service')
                        if service_elem is not None:
                            service_name = service_elem.get('name', 'unknown')
                            product = service_elem.get('product', '')
                            version = service_elem.get('version', '')
                            service_version = service_name
                            if product:
                                service_version += " " + product
                            if version:
                                service_version += " " + version
                            service_version = service_version.strip()
                        else:
                            service_version = "unknown"
                        port_service_mapping[port_id] = {
                            "protocol": protocol,
                            "service_version": service_version
                        }
        return {"open_ports_services": port_service_mapping}
    except Exception as e:
        logging.error("nmap 점검 실패: %s", str(e))
        return {"error": str(e)}

def check_firewall_rules():
    """
    방화벽 점검 함수:
    - 방화벽이 기동중인지 여부와 방화벽 제품/버전 정보를 확인합니다.
    - 우선 ufw 명령어를 사용하여 "ufw status verbose"와 "ufw version"으로 점검하며,
      ufw 사용에 실패하면 iptables로 대체합니다.
    """
    try:
        cmd = ["ufw", "status", "verbose"]
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True)
        first_line = result.splitlines()[0] if result.splitlines() else ""
        running = True if "active" in first_line.lower() else False
        try:
            version_cmd = ["ufw", "version"]
            version_result = subprocess.check_output(version_cmd, stderr=subprocess.STDOUT, universal_newlines=True)
            version_info = version_result.strip()
        except Exception as inner_e:
            version_info = "unknown"
        logging.info("ufw 방화벽 점검: running=%s, version=%s", running, version_info)
        return {"firewall_running": running, "firewall_product": "ufw", "firewall_version": version_info}
    except Exception as e:
        logging.warning("ufw 점검 실패: %s", str(e))
        try:
            cmd = ["iptables", "-L", "-n", "-v"]
            subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True)
            logging.info("iptables 방화벽 사용 (제품/버전 정보 없음)")
            return {"firewall_running": True, "firewall_product": "iptables", "firewall_version": "unknown"}
        except Exception as e2:
            logging.error("iptables 점검 실패: %s", str(e2))
            return {"error": str(e2)}

def check_security_updates():
    """
    보안 업데이트 점검 함수:
    - 시스템에 적용 가능한 보안 업데이트가 있는지 점검합니다.
    - Debian 기반: "apt-get -s upgrade" 명령어 시뮬레이션 결과에서 'Inst'와 'security'가 포함된 항목 필터링
    - RedHat 기반: "yum check-update --security" 명령어를 실행하여 업데이트 목록 확인
    - 지원되지 않는 시스템이면 에러 메시지를 반환합니다.
    """
    updates = []
    if os.path.exists("/etc/debian_version"):
        try:
            cmd = ["apt-get", "-s", "upgrade"]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True)
            for line in output.splitlines():
                if line.startswith("Inst") and "security" in line.lower():
                    updates.append(line.strip())
            logging.info("Debian 기반 보안 업데이트 점검 결과: %d개", len(updates))
            return {"security_updates": updates}
        except Exception as e:
            logging.error("Debian 기반 보안 업데이트 점검 실패: %s", str(e))
            return {"error": str(e)}
    elif os.path.exists("/etc/redhat-release"):
        try:
            cmd = ["yum", "check-update", "--security"]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            output = result.stdout
            for line in output.splitlines():
                line = line.strip()
                if line and not line.startswith("Loaded plugins:") and not line.startswith("Security:") and not line.startswith("Obsoleting Packages"):
                    updates.append(line)
            logging.info("RedHat 기반 보안 업데이트 점검 결과: %d개", len(updates))
            return {"security_updates": updates}
        except Exception as e:
            logging.error("RedHat 기반 보안 업데이트 점검 실패: %s", str(e))
            return {"error": str(e)}
    else:
        msg = "지원되지 않는 시스템입니다. 보안 업데이트 점검 기능은 Debian 또는 RedHat 기반 시스템에서만 지원됩니다."
        logging.error(msg)
        return {"error": msg}

def check_user_accounts():
    """
    사용자 계정 점검 함수:
    - /etc/passwd 파일을 읽어 사용자 계정 정보를 파싱합니다.
    - 각 계정은 "username", "password", "uid", "gid", "comment", "home", "shell" 정보를 포함합니다.
    """
    accounts = []
    passwd_file = "/etc/passwd"
    if not os.path.exists(passwd_file):
        logging.error("파일 %s 가 존재하지 않습니다.", passwd_file)
        return {"error": f"파일 {passwd_file}를 찾을 수 없습니다."}
    
    try:
        with open(passwd_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(":")
                if len(parts) < 7:
                    continue
                username, passwd_field, uid, gid, comment, home, shell = parts[:7]
                account = {
                    "username": username,
                    "password": passwd_field,  # shadow 파일 사용 시 'x'로 표시됨
                    "uid": uid,
                    "gid": gid,
                    "comment": comment,
                    "home": home,
                    "shell": shell
                }
                accounts.append(account)
        logging.info("사용자 계정 점검 성공: %d개 계정 발견", len(accounts))
        return {"user_accounts": accounts}
    except Exception as e:
        logging.error("사용자 계정 점검 실패: %s", str(e))
        return {"error": str(e)}

def check_dangerous_users():
    """
    위험한 사용자 계정 점검 함수:
    - /etc/passwd 파일에서 읽은 사용자 계정 중 보안상 위험한 계정만 필터링합니다.
    
    위험한 계정의 조건:
      1. UID가 0이면서 username이 "root"가 아닌 경우.
      2. 패스워드 필드가 비어있는 경우.
      3. username이 의심스러운 단어("admin", "test", "backdoor", "hacker")에 해당하는 경우.
      4. 홈 디렉토리가 존재하지 않는 경우.
    
    위험한 계정이 없으면 "없음"이라고 반환합니다.
    """
    dangerous = []
    user_accounts_result = check_user_accounts()
    if "error" in user_accounts_result:
        return {"error": "사용자 계정 점검 실패: " + user_accounts_result["error"]}
    
    accounts = user_accounts_result.get("user_accounts", [])
    suspicious_names = ["admin", "test", "backdoor", "hacker"]
    
    for account in accounts:
        is_dangerous = False
        try:
            uid_int = int(account.get("uid", ""))
        except ValueError:
            uid_int = None
        if uid_int == 0 and account.get("username", "").lower() != "root":
            is_dangerous = True
        if account.get("password", "") == "":
            is_dangerous = True
        if account.get("username", "").lower() in suspicious_names:
            is_dangerous = True
        home_dir = account.get("home", "")
        if home_dir and not os.path.exists(home_dir):
            is_dangerous = True
        if is_dangerous:
            dangerous.append(account)
    
    logging.info("위험한 사용자 계정 점검: %d개 위험한 계정 발견", len(dangerous))
    if not dangerous:
        return {"dangerous_users": "없음"}
    else:
        return {"dangerous_users": dangerous}

def search_exploitdb_info(query):
    """
    ExploitDB 정보 검색 함수:
    - 'searchsploit -j <query>' 명령어를 사용하여 ExploitDB에서 관련 정보를 JSON 형식으로 검색합니다.
    - 반환 값은 ExploitDB의 exploit 목록(제목, EDB-ID, 날짜, 경로 등)을 포함하는 리스트입니다.
    """
    try:
        cmd = ["searchsploit", "-j", query]
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True)
        data = json.loads(output)
        results = data.get("RESULTS_EXPLOIT", [])
        exploit_list = []
        for item in results:
            title = item.get("Title", "Unknown")
            edb_id = item.get("EDB-ID", "Unknown")
            date = item.get("Date", "")
            path = item.get("Path", "")
            platform_info = item.get("Platform", "")
            exploit_list.append({
                "Title": title,
                "EDB-ID": edb_id,
                "Date": date,
                "Path": path,
                "Platform": platform_info
            })
        return {"search_query": query, "results": exploit_list}
    except Exception as e:
        logging.error("ExploitDB 검색 실패: %s", str(e))
        return {"error": str(e)}

def check_exploitdb_numbers(report):
    """
    ExploitDB 검색 함수:
    - 수집된 보안 점검 정보(특히 "취약점 점검" 항목의 메시지)를 기반으로 ExploitDB에서 관련 정보를 검색합니다.
    - 각 취약점 메시지를 쿼리로 하여 search_exploitdb_info()를 호출하고 결과를 반환합니다.
    """
    vulnerabilities = report.get("취약점 점검", [])
    exploitdb_results = []
    if isinstance(vulnerabilities, list):
        for vuln in vulnerabilities:
            search_result = search_exploitdb_info(vuln)
            if "results" in search_result and search_result["results"]:
                exploitdb_results.append({
                    "vulnerability": vuln,
                    "ExploitDB_info": search_result["results"]
                })
    if not exploitdb_results:
        exploitdb_results.append({"message": "관련 ExploitDB 정보가 발견되지 않았습니다."})
    return {"ExploitDB 검색 결과": exploitdb_results}

def check_vulnerabilities(report):
    """
    취약점 점검 함수:
    - 수집된 보안 점검 정보를 분석하여, 아래 항목에 대해 취약점이 있는지 평가합니다.
      1. 방화벽: 기동 상태가 아닌 경우 취약.
      2. 보안 업데이트: 업데이트 항목이 존재하면 취약.
      3. 위험한 사용자 계정: 위험한 계정이 존재하면 취약.
      4. 네트워크 포트: 위험한 서비스가 동작 중인 포트(예: 21, 23, 1433, 1521, 3306)가 있으면 취약.
    - 취약점이 하나도 없으면 "취약한 항목이 발견되지 않았습니다."라고 출력합니다.
    """
    vulnerabilities = []
    
    # 1. 방화벽 취약점
    fw = report.get("방화벽 점검", {})
    if not fw.get("firewall_running", False):
        vulnerabilities.append("방화벽이 비활성화 상태입니다.")
    
    # 2. 보안 업데이트 취약점
    updates = report.get("보안 업데이트 점검", {}).get("security_updates", [])
    if isinstance(updates, list) and len(updates) > 0:
        vulnerabilities.append("보안 업데이트가 적용되지 않았습니다. 업데이트 항목: " + ", ".join(updates))
    
    # 3. 위험한 사용자 계정 취약점
    dangerous = report.get("사용자 계정 점검", {}).get("dangerous_users")
    if dangerous and dangerous != "없음":
        if isinstance(dangerous, list) and len(dangerous) > 0:
            user_list = ", ".join([user.get("username", "unknown") for user in dangerous])
            vulnerabilities.append("위험한 사용자 계정이 존재합니다: " + user_list)
    
    # 4. 네트워크 포트 취약점
    ports = report.get("네트워크 점검", {}).get("open_ports_services", {})
    risky_ports = []
    risky_port_numbers = {"21", "23", "1433", "1521", "3306"}
    for port, info in ports.items():
        if port in risky_port_numbers:
            service_version = info.get("service_version", "unknown")
            risky_ports.append(f"포트 {port} ({service_version})")
    if risky_ports:
        vulnerabilities.append("위험한 서비스가 동작 중인 포트가 열려 있습니다: " + ", ".join(risky_ports))
    
    if not vulnerabilities:
        vulnerabilities.append("취약한 항목이 발견되지 않았습니다.")
    
    return {"취약점 점검": vulnerabilities}

def run_security_check():
    """
    보안 점검 실행 함수:
    - 운영체제, 네트워크, 방화벽, 보안 업데이트, 사용자 계정 점검을 실행한 후,
      수집된 정보를 바탕으로 취약점 점검까지 실행하고,
      추가로 ExploitDB 검색까지 수행하여 결과를 하나의 딕셔너리로 반환합니다.
    """
    results = {
        "운영체제 점검": check_os_version(),
        "네트워크 점검": check_ports_nmap(),
        "방화벽 점검": check_firewall_rules(),
        "보안 업데이트 점검": check_security_updates(),
        "사용자 계정 점검": check_dangerous_users()  # 위험한 사용자만 출력 (없으면 "없음")
    }
    vuln = check_vulnerabilities(results)
    results["취약점 점검"] = vuln["취약점 점검"]
    # ExploitDB 검색 추가
    exploitdb = check_exploitdb_numbers(results)
    results["ExploitDB 검색 결과"] = exploitdb["ExploitDB 검색 결과"]
    return results

def print_security_report(report):
    """
    보안 점검 결과를 보기 좋게 JSON 형식으로 출력하는 함수.
    """
    print("=== 보안 점검 결과 ===")
    print(json.dumps(report, indent=4, ensure_ascii=False))

def save_security_report(report, filename=None):
    """
    보안 점검 결과를 파일로 저장하는 함수:
    - JSON 형식으로 보기 좋게 (indented) 저장합니다.
    - filename이 지정되지 않으면 "security_report_YYYYMMDD_HHMMSS.json" 형식으로 저장합니다.
    """
    if filename is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.json"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        logging.info("보안 점검 결과를 파일로 저장했습니다: %s", filename)
        print(f"보안 점검 결과가 '{filename}' 파일에 저장되었습니다.")
    except Exception as e:
        logging.error("보안 점검 결과 파일 저장 실패: %s", str(e))
        print("보안 점검 결과 파일 저장에 실패했습니다.")

def save_summary_report(start_time, end_time, report, filename=None):
    """
    보안 점검 요약 결과를 파일로 저장하는 함수:
    - "점검시작 시간 ~ 점검 종료 시간 : 발견된 취약점" 형식으로 저장합니다.
    - filename이 지정되지 않으면 "security_summary_YYYYMMDD_HHMMSS.txt" 형식으로 저장합니다.
    """
    # 취약점 항목 추출 (리스트 또는 문자열일 수 있음)
    vulnerabilities = report.get("취약점 점검", [])
    if isinstance(vulnerabilities, list):
        vuln_str = ", ".join(vulnerabilities)
    else:
        vuln_str = vulnerabilities

    start_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
    end_str = end_time.strftime("%Y-%m-%d %H:%M:%S")
    summary = f"{start_str} ~ {end_str} : {vuln_str}"
    
    if filename is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_summary_{timestamp}.txt"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(summary)
        logging.info("보안 점검 요약 결과를 파일로 저장했습니다: %s", filename)
        print(f"보안 점검 요약 결과가 '{filename}' 파일에 저장되었습니다.")
    except Exception as e:
        logging.error("보안 점검 요약 결과 파일 저장 실패: %s", str(e))
        print("보안 점검 요약 결과 파일 저장에 실패했습니다.")

def main():
    """
    메인 함수:
    - 보안 점검 시작 및 종료 시간을 출력하고, 점검 결과를 콘솔에 표시한 후,
      결과를 JSON 파일과 요약 텍스트 파일로 저장합니다.
    """
    start_time = datetime.datetime.now()
    print("[보안 점검 시작 시간]")
    print(" ", start_time.strftime("%Y-%m-%d %H:%M:%S"))
    logging.info("보안 점검 시작: %s", start_time.strftime("%Y-%m-%d %H:%M:%S"))
    
    security_report = run_security_check()
    print("[보안 점검 결과]")
    print_security_report(security_report)
    
    # 결과를 JSON 파일로 저장
    save_security_report(security_report)
    
    end_time = datetime.datetime.now()
    print("[보안 점검 종료 시간]")
    print(" ", end_time.strftime("%Y-%m-%d %H:%M:%S"))
    logging.info("보안 점검 종료: %s", end_time.strftime("%Y-%m-%d %H:%M:%S"))
    
    # 요약 파일 저장: "점검시작 시간 ~ 점검 종료 시간 : 발견된 취약점" 형식
    save_summary_report(start_time, end_time, security_report)

if __name__ == "__main__":
    main()
