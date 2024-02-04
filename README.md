# eBreached: An OSINT Blue Team tool for detecting breached emails and corresponding passwords. 
By Roberto Dillon. (c) 2024

eBreached is a simple Python script that queries https://breachdirectory.org to check whether specific email accounts have been breached.

Registration for obtaining an API key is required and do bear in mind that, at the moment of writing, the BreachDirectory
free plan allows for only 10 searches per month (https://rapidapi.com/rohan-patra/api/breachdirectory).

The program prompts the user to enter an email and API key (either as keyed-in parameters or as saved files),
checks if the email(s) has been breached, and, if so, it saves the relevant information (including password hashes, if available) to a CSV file with the current date and time in the filename.

Examples:
> python ebreached.py -e <email@email.com> -k <api_key>

to run the script and provide a single email and API key manually.

> python ebreached.py -l <file.csv> -f <api_key.txt>

to run the  script by loading a list of emails plus the API key from the corresponding files.

The script can be run with the -h flag to display the help message and understand how to use the different options.

Example:
> python ebtreache.py -h

The output CSV file will contain all results retrieved from breachdirectory.org. Feel free to customize the output to suit your needs.
Make sure to handle your API key securely, and never share it in public scripts or repositories.

Be sure you install the following libraries if needed:
> pip install requests csv argparse datetime time
