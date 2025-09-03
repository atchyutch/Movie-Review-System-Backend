import requests
import json

try:

	URLclear = "http://127.0.0.1:5000/clear"
	r_clear = requests.get(url = URLclear)

	URL = "http://127.0.0.1:5000/create_user"
	PARAMS = {'first_name': 'James', 'last_name': 'Mariani', 'username': 'jmariani', 'email_address': 'james@mariani.com', 'password': 'Examplepassword1', 'moderator': True, 'critic': True, 'salt': 'FE8x1gO+7z0B'}

	r = requests.post(url = URL, data = PARAMS)
	data = r.json()


	solution = {"status": 1, "pass_hash": "9060e88fe7f9a95839a19926d517a442da58f47c48edc2f37e1c3aea5f8956fc"}

	for key in solution:
		if solution[key] != data[key]:
			print('Test Failed')
			quit()
			
	print('Test Passed')
	
except:
	print('Test Failed')