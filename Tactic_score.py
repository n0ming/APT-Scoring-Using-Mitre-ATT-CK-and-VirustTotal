import csv
def score(permission):
            if permission == "SYSTEM":
                return 5
            elif permission == "root":
                return 5
            elif  permission == "Administrator":
                return 3
            elif  permission == "User":
                return 1
            elif  permission == "Remote Desktop User":
                return 1
            else:
                print(f"error for permission: {permission}")
                return 0 
hash_values = set()  # 중복을 허용하지 않는 set을 정의
IDs=[]
with open('result_with_hash_date.csv', 'r') as csvfile:
    csv_reader = csv.reader(csvfile)
    next(csv_reader)
    for row in csv_reader:
        hash_value = row[0]  # CSV 파일에서 hash 값이 있는 열의 인덱스에 따라 수정
        hash_values.add(hash_value)
counts=[]
# 중복이 없는 해쉬 값들이 포함된 리스트로 변환
total_hash=[]
total_defense_bypassed_score=[]
unique_hashes = list(hash_values)
with open('Tactic_score.csv', mode='a', encoding='utf-8', newline='') as file:        
    writer = csv.writer(file)
    with open('result_with_hash_date.csv', 'r') as csvfile:
        csv_reader = csv.DictReader(csvfile)
        count=0
        for row in csv_reader:
            md5=row['MD5'] 
            ID=row['Mitre_ID']
            Tactic_ID=row['Tactic_ID']
            if row['Tactic_ID'] != 'TA0043' and row['Tactic_ID'] != 'TA0042':
                print(ID)
                ID= ID.replace(".", "_")
                with open(f'{ID}.csv', 'r') as csvfile:
                    csv_reader = csv.DictReader(csvfile)
                    for row in csv_reader:
                        print(row)
                        if row['Title'] == 'Tactics' or row['Title'] == 'Tactic':
                            values = row['Value'].strip().split(',')
                            count = len(values)
                            print("dd",count)
                #print(md5)
                #print(count)
                ID= ID.replace("_", ".")
                row = [md5, ID,count]
                writer.writerow(row) 
                count=0
            else:
                row = [md5, ID,-1]
                writer.writerow(row) 
    print(IDs)
