import csv
import json
import os
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# silence unverified HTTPS warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def scan_registers(csv_path, out_json, phrase_out_json, workers=100):
	"""Read CSV of urlscan results, check https://<domain>/register for HTTP 200.
	Writes JSON list of successful domains to out_json.
	Also writes unique domains whose response contains
	"Simple, Secure, Reliable" to phrase_out_json.
	"""
	domains = []
	with open(csv_path, newline='', encoding='utf-8') as f:
		reader = csv.DictReader(f)
		for row in reader:
			dom = row.get('Page Apex Domain')
			if dom:
				domains.append(dom.strip())

	print(f"[*] Loaded {len(domains)} domains")
	results = []
	phrase_results = []
	phrase_seen = set()
	completed = 0
	phrase = "Simple, Secure, Reliable"

	def check(domain):
		url = f"https://{domain}/register"
		try:
			r = requests.get(url, verify=False, timeout=15)
			if r.status_code == 200:
				return domain, (phrase in r.text)
		except Exception:
			return None
		return None

	with ThreadPoolExecutor(max_workers=workers) as ex:
		futures = {ex.submit(check, d): d for d in domains}
		for fut in as_completed(futures):
			res = fut.result()
			completed += 1
			if res:
				domain, has_phrase = res
				results.append(domain)
				if has_phrase and domain not in phrase_seen:
					phrase_seen.add(domain)
					phrase_results.append(domain)
					print(f"[+] Phrase match: {domain} ({completed}/{len(domains)})")
				else:
					print(f"[+] Found: {domain} ({completed}/{len(domains)})")
			else:
				print(f"[-] Progress: {completed}/{len(domains)}")

	# write JSON
	with open(out_json, 'w', encoding='utf-8') as jf:
		json.dump(results, jf, indent=2)
	with open(phrase_out_json, 'w', encoding='utf-8') as pf:
		json.dump(phrase_results, pf, indent=2)

	print(f"[*] Completed! Found {len(results)} domains")
	print(f"[*] Phrase matches written: {len(phrase_results)}")
	return results

if __name__ == '__main__':
	base = os.path.dirname(__file__)
	csv_path = os.path.join(base, 'logs', 'urlscan.csv')
	out_json = os.path.join(base, 'registers.json')
	phrase_out_json = os.path.join(base, 'registers_simple_secure_reliable.json')
	scan_registers(csv_path, out_json, phrase_out_json)
