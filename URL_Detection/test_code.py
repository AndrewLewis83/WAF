from mlurl import URLScan

def main():

	#instantiate URLscan()
	us = URLScan()
	
	# run updateLists() once per week, looking for updates for both URL lists (benign and malicious) and retrain the model on the new lists
	us.updateLists()
	
	# this checks if the URL is malcious or not.
	result = us.classify_url("macrumors.com")
	if result == 0:
		print("URL is not malicious")
	else:
		print("URL is potentially malicious")
		
	# Virus total function checks the result of the classifier against
	# virus total to ensure that it is making the correct decision.	
	# This method uses an api and has a request limit associated with it. It may be that we can't use it in our
	# project for that reason. 
	if us.virus_total(result, "macrumors.com") == True:
		print("URL is not malicious")
	else:
		print("URL is potentially malicious") 

main()

