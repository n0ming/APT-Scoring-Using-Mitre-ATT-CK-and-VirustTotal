import csv
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
data_list = []
values=[]
values2=[]
len1=0
len2=0
ID_values=[]
total_defense_bypassed_score=[]
unique_hashes = list(hash_values)
with open('Defense Bypassed_score.csv', mode='a', encoding='utf-8', newline='') as file:        
    writer = csv.writer(file)
    with open('result_with_hash_date.csv', 'r') as csvfile:
        csv_reader = csv.DictReader(csvfile)
        count=0
        for row in csv_reader:
            md5=row['MD5'] 
            ID=row['Mitre_ID']
            Tactic_ID=row['Tactic_ID']
            if row['Tactic_ID'] == 'TA0005' or row['Tactic_ID'] == 'TA0008':
                print(ID)
                ID= ID.replace(".", "_")
                with open(f'{ID}.csv', 'r') as csvfile:
                    csv_reader = csv.DictReader(csvfile)
                    for row in csv_reader:
                        if row['Title'] == 'Defense Bypassed':
                            values=row['Value'].split(', ')
                            print(values)
                            print(len(values))
                            len1=len(values)
                        if row['Title']=='Sub-techniques':
                            values2 =row['Value'].split(', ')
                            print(values2)
                            len2=len(values2)
                        if len1 ==1:
                            count =1
                            if len2 >=2:
                                coount=3
                        if len1 > 1:
                            count=5
                ID= ID.replace("_", ".")
                row = [md5, ID,count]
                writer.writerow(row) 
                count=0
                values=[]
            else:
                row = [md5, ID,-1]
                writer.writerow(row) 
    print(IDs)

