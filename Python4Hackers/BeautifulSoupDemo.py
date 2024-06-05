import requests
from bs4 import BeautifulSoup

page = requests.get("https://247ctf.com/scoreboard")
#print(page.text)
soup = BeautifulSoup(page.content,"html.parser")
print(soup.text)
print(soup.title)
print(soup.name)
print(soup.string)
#print(soup.find("a"))

#for line in soup.find_all("a"):
#    print(line)
#    print(line.get('href'))


table=soup.find("table")
table_body=table.find("tbody")
rows=table_body.find_all("tr")

for row in rows:
    #print("---")
    #print(row)
    cols = [x.text.strip() for x in row.find_all("td")]
    #print(cols)
    print("{} is in {} place with {} points".format(cols[2],cols[0],cols[4]))



    