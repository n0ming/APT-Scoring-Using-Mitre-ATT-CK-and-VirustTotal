import requests
import json
import csv
ioc_dict=[]
hashes=[]
with open('link_ioc_blink_noerror.csv', 'r') as csvfile:
    csv_reader = csv.DictReader(csvfile)
    for row in csv_reader:
        if not row['MD5'] == '':
            ioc_values = row['MD5'].strip() # IOCs 값을 콤마로 분리하여 리스트로 저장
            ioc_dict.append(ioc_values)
            hash = row['Hash'].strip()
            hashes.append(hash)
# VirusTotal API 키
api_key = '32c69ae10ec6ab812b099068e349fbf48ce48b47d0c4924da83bb62a3677dbe9'
results = []
for md5,hash in zip(ioc_dict,hashes):
    
    # 파일의 SHA-256 해시
    file_hash = md5
    # VirusTotal API URL
    url = f"https://www.virustotal.com/api/v3/files/{md5}/behaviour_mitre_trees"

    # API 요청 헤더
    headers = {
        "x-apikey": api_key
    }

    # API 요청
    response = requests.get(url, headers=headers)

    # 응답을 JSON으로 변환
    data = response.json()
    with open('output2.json', 'a') as json_file:
        json.dump(data, json_file, indent=2)
    # 부모-자식 관계를 저장할 딕셔너리
    relation_dict = {}
    tactic_ids = []
    mitre_ids = []
    sandbox_data = data.get("data", {})
    keys = sandbox_data.keys()
    for key in keys:
        # 'sandbox_name' 필드가 딕셔너리인 경우 처리
        sandbox_data = data.get("data", {}).get(f"{key}", {})
        if isinstance(sandbox_data, dict):
            # 'tactics' 필드가 리스트인 경우 각 항목에 대해 처리
            for tactic in sandbox_data.get('tactics', []):
                # 'id' 값을 추출하여 tactic_ids에 추가
                tactic_id = tactic.get('id')
                tactic_ids.append(tactic_id)
                
                # 'techniques' 필드가 리스트인 경우 각 항목에 대해 처리
                for technique in tactic.get('techniques', []):
                    # 'id' 값을 추출하여 mitre_ids에 추가
                    mitre_id = technique.get('id')
                    mitre_ids.append(mitre_id)

                    # 부모-자식 관계를 뒤집어서 저장
                    if tactic_id not in relation_dict:
                        relation_dict[tactic_id] = set([mitre_id])
                    else:
                        relation_dict[tactic_id].add(mitre_id)


    # 파일 해시를 키로 가지는 딕셔너리 생성
    result_dict = {file_hash: {k: list(v) for k, v in relation_dict.items()}}

    # 결과 리스트에 추가
    results.append(result_dict)
    print(results)
# 모든 결과가 담긴 리스트를 JSON 파일로 저장
with open('output.json', 'w') as json_file:
    json.dump(results, json_file, indent=2)

print("Tactic IDs:", tactic_ids)
print("MITRE IDs:", mitre_ids)
print("Relation Dictionary:", relation_dict)
print("Data saved to 'output.json'")
