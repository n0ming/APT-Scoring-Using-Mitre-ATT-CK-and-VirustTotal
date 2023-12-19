from selenium import webdriver
from selenium.webdriver.common.by import By
import csv

options = webdriver.ChromeOptions()
browser = webdriver.Chrome(options=options)
ioc_dict = []
ioc_values = []
hash = []
IDs=[]
with open('result_with_hash_date.csv', 'r') as csvfile:
    csv_reader = csv.DictReader(csvfile)
    for row in csv_reader:    
        ioc_values = row['Mitre_ID'] # IOCs 값을 콤마로 분리하여 리스트로 저장
        IDs.append(ioc_values)
IDs_with_dot = [id_value for id_value in IDs if '.' in id_value]
id=[]
for i in range(len(IDs_with_dot)):
    # Use ID instead of IDs[i] and iterate over the length of IDs_with_dot
    IDs_with_dot[i] = IDs_with_dot[i].replace(".", "/")
for ID in IDs_with_dot:
    try:
        with open(f'{ID}.csv', 'r') as csvfile:
            continue
    except:
        id.append(ID)
print(id)
print(len(id))
unique_list = list(set(id))
print(unique_list)
print(len(unique_list))
for ID in unique_list:
    url = f"https://attack.mitre.org/techniques/{ID}/"
    browser.get(url)
    browser.implicitly_wait(5)

    data = []

    try:
        elements = browser.find_elements(By.CLASS_NAME, "col-md-4")
        for element in elements:
            bufs = element.find_elements(By.CLASS_NAME, "col-md-11.pl-0")
            for buf in bufs:
                sufs = buf.text.split(": ", 1)
                if len(sufs) == 2:
                    data.append({"Title": sufs[0], "Value": sufs[1]})

    except Exception as e:
        print("추출에 실패했습니다.", e)


    header = ["Title", "Value"]
    ID = ID.replace("/", "_")
    with open(f'{ID}.csv', 'w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=header)

        # Write header
        writer.writeheader()

        # Write data
        writer.writerows(data)
browser.quit()
