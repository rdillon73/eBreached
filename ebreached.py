'''
eBreached v.0.1.0
(c) 2024 Roberto Dillon - https://github.com/rdillon73/

This script queries https://breachdirectory.org to check whether specific email accounts have been breached.
Registration for obtaining an API key is required and do bear in mind that, at the moment of writing, the BreachDirectory
free plan allows for only 10 searches per month (https://rapidapi.com/rohan-patra/api/breachdirectory).

The program prompts the user to enter an email and api key (either as keyed-in parameters or as files),
checks if the email(s) has been breached, and saves the results to a CSV file with the current date and time in the filename.

The CSV file containing the email addresses to be checked needs to have all emails in the first row, with each email in its own cell.

You can run the script with the -h option to see the help message and understand how to use the different options.

The output CSV file will contain all results retrieved from breachdirectory.org. Feel free to customize the output to suit your needs.
Make sure to handle your API key securely, and never share it in public scripts or repositories.

To run the program , be sure you install the following libraries, if needed:
> pip install requests csv argparse datetime time
'''

import csv
import argparse
import time
from datetime import datetime
import requests

def print_intro():
    print("========================================")
    print("=                                      =")
    print("=          eBreached v.0.1.0           =")
    print("= a tool for detecting breached emails =")
    print("=         by Roberto Dillon            =")
    print("=     https://github.com/rdillon73     =")
    print("=                                      =")
    print("========================================")


# this is the core function. Query string and headers are provided by the breachdirectory documentation.
def check_email_pwned(email, api_key):
    url = "https://breachdirectory.p.rapidapi.com/"
    querystring = {"func": "auto", "term": email}
    headers = {
        "X-RapidAPI-Key": api_key,
        "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
    }
    print(f"Checking breaches for {email}... Please wait.")
    response = requests.get(url, headers=headers, params=querystring)

    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        print ("Error 404 when connecting to BreachDirectory!")
        return None
    elif response.status_code == 500:
        print ("Error 500: Either no records found or Internal Server Error.")
        return None
    else:
        print(f"There was an error ({response.status_code}) connecting to BreachDirectory (e.g. invalid API key or exceeded number of requests)")
        return None

def save_to_csv(output_filename, email_results):
    with open(output_filename, mode="w", newline="", encoding="utf-8") as file:
        # define the columns in the csv file where the data will be exported
        fieldnames = ["Email", "Password", "Sha1", "Hash", "Sources"]
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        # parse through all the retrieved data, including passwords, hashes and breached sources
        # and export the results to a csv file
        try:
            for email, email_data in email_results.items():
                results = email_data.get("result", [])
                for result in results:
                    password = result.get("password", "")
                    sha1 = result.get("sha1", "")
                    hash_value = result.get("hash", "")
                    sources = result.get("sources", [])

                    writer.writerow({
                        "Email": email,
                        "Password": password,
                        "Sha1": sha1,
                        "Hash": hash_value,
                        "Sources": ", ".join(sources) if sources else ""
                    })
        except:
            print("Nothing to report. Quitting!")
            exit()


def check_emails_from_file(input_filename, api_key):
    try:
        with open(input_filename, mode="r", newline="", encoding="utf-8") as file:
            reader = csv.reader(file)
            emails = next(reader)  # Read the first row as emails.
            email_results = {email: [] for email in emails}

            for email in email_results:
                #print(f"Checking breaches for {email}... Please wait.")
                breaches = check_email_pwned(email, api_key)
                if breaches:
                    email_results[email] = breaches

                # Add a 1 second delay between searches
                # this is a requirement from the breachdirectory free plan. Adjust accordingly or delete if you have a paid subscription plan!
                time.sleep(1)

        return email_results
    except:
        print("Error opening file. Quitting!")
        exit()
        
def load_api_key(api_key_file):
    api_key = ""
    with open(api_key_file, "r") as key_file:
        api_key = key_file.read().strip()
        if api_key == "":
            print("API key not found in the specified file.")
        else:
            print("API key loaded successfully.")
    return api_key

def print_help():
    print("Usage examples:")
    print(
        "python ebreached.py -e <email> -k <api_key>        : Check a single email for breaches using the provided API key.")
    print(
        "python ebreached.py -l <file.csv> -k <api_key>     : Check emails from a CSV file for breaches using the provided API key.")
    print(
        "python ebreached.py -l <file.csv> -f <api_key.txt> : Check emails from a CSV file for breaches using the API key loaded from a text file.")
    print("python ebreached.py -h                             : Display this help message.")


# the main function: parses arguments and acts accordingly
if __name__ == "__main__":
    # showtime!
    print_intro()
    # initialize results with an empty string
    email_results = ""

    parser = argparse.ArgumentParser(
        description="Check email(s) for breaches using breachdirectory.org. Results are saved in a csv file. API key required.")
    parser.add_argument("-e", dest="single_email", help="Specify a single email to check for breaches.")
    parser.add_argument("-l", dest="file_path", help="Specify a CSV file containing a list of emails to check. All emails in the first row, one per column.")
    parser.add_argument("-k", dest="api_key", help="Specify the API key for breachdirectory.org.")
    parser.add_argument("-f", dest="api_key_file",
                        help="Specify a text file containing the API key for breachdirectory.org.")
    args = parser.parse_args()

    # if not enough parameters are provided, automatically calls help function.
    if not (args.single_email or args.file_path) or not (args.api_key or args.api_key_file):
        print_help()
    else:
        api_key = args.api_key if args.api_key else load_api_key(args.api_key_file)

        if args.single_email:
            email_results = {args.single_email: check_email_pwned(args.single_email, api_key)}
        elif args.file_path:
            email_results = check_emails_from_file(args.file_path, api_key)

        if email_results:
            current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            output_filename = f"{current_datetime}_breach_results.csv"
            save_to_csv(output_filename, email_results)
            print(f"Results saved to CSV file: {output_filename}.")
            print("Only emails with detected breaches are listed in the file.")


