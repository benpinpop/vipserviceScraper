import main

input_url = input("Enter the URL to check: ")

if main.is_site_reported(input_url):
    print(f"{input_url} is already reported on ScamBusters.")
    continue_scanning = input("Would you like to continue with scanning and submission? (y/n): ")

    if continue_scanning.lower() != 'y':
        print("Exiting.")
        exit(0)


scan_site_result = main.scan_website_with_urlscan(input_url)
scan_site_result_id = scan_site_result.get("api")


