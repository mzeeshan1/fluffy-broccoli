import json


data = {}
data['people'] = []

for i in range(200000):
    data['people'].append({'regexp': str(i+i+151234), 'name': str(i+i+151234), 'allow': True})
    # jstr = json.dumps(data,indent=4)
with open('data.txt', 'w') as outfile:
    json.dump(data, outfile)

print(jstr)


