import yara

'''
rules = yara.compile(filepaths={
    "malware_set1 rules": b"C:/Users/bits/Desktop/licenta/phishme/functionalitati/yararules/allrules.yar"})
'''

def yara_match(file_path, rules):
    try:
        matches = rules.match(file_path, timeout=60)
        return matches
    #except TimeoutError:
    #    print("the time is running out")
    except:
        print("something")
