from selenium import webdriver
from selenium.webdriver.common.by import By
import csv

options = webdriver.ChromeOptions()
browser = webdriver.Chrome(options=options)
ioc_dict = []
ioc_values = []
hash = []
IDs=[]
total_hash=[]
hash_values = set()
with open('result_with_hash_date.csv', 'r') as csvfile:
    csv_reader = csv.DictReader(csvfile)
    next(csv_reader)
    for row in csv_reader:    
        ioc_values = row['Mitre_ID'] # IOCs 값을 콤마로 분리하여 리스트로 저장
        IDs.append(ioc_values)

header = ["Hash", "Tactic","Score"]
with open('Procedure examples.csv', mode='a', encoding='utf-8', newline='') as file: 
    writer = csv.writer(file)

    # Write header
    writer.writerow(header)
for i in range(len(IDs)):
    # Use ID instead of IDs[i] and iterate over the length of IDs_with_dot
    IDs[i] = IDs[i].replace(".", "/")
unique_hashes = sorted(set(IDs))


count = 0
for ID in unique_hashes:
    print(len(unique_hashes))
    url = f"https://attack.mitre.org/techniques/{ID}/"
    browser.get(url)
    browser.implicitly_wait(5)

    data = []

    try:
        elements = browser.find_element(By.CLASS_NAME, "table.table-bordered.table-alternate.mt-2")
        rows = elements.find_elements(By.TAG_NAME, "tr")
        print(len(rows))
        data.append(len(rows)-1)
        date = len(rows)-1

    except Exception as e:
        print("추출에 실패했습니다.", e)

    print(total_hash)
    header = ["ID", "Score"]
    with open('Procedure examples.csv', mode='a', encoding='utf-8', newline='') as file: 
        writer = csv.writer(file)

        # Write data
        if date:
            row = [ID, date]
        else:
            row = [ID, '-1']
        writer.writerow(row)
    ID = ID.replace("/", "_")
    count = count+1
browser.quit()
