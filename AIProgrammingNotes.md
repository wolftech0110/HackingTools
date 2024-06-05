### Methodology
- What problem do i want to solve?
-- Work Problem Consuming data?
-- 



#### Programming Phases
Building a program in Python generally involves several steps, which can be broken down as follows:

Requirement Analysis:

        Understand what the program is supposed to do.
        Determine the requirements and how they will be met in your program.

Planning:

        Choose the right Python version.
        Decide on libraries and frameworks needed based on the requirements.
        Sketch out the program structure and its components.

Setting Up the Development Environment:

        Install Python and necessary libraries.
        Set up a code editor or an integrated development environment (IDE).

Design:

        Create the architecture of your program.
        Design the user interface if applicable.
        Plan out the data models and storage if needed.

Coding:

        Write the Python code, starting with core functionality.
        Develop in iterations, adding features one by one.
        Use version control systems like Git to manage your code.

Writing Tests:

        Write unit tests for your code to ensure each part works correctly.
        Consider using Test-Driven Development (TDD) by writing tests before writing the code that fulfills them.

Debugging:

        Test your program to find bugs.
        Use debugging tools to locate and fix issues in your code.

Refactoring:

        Clean up your code by refactoring it for readability and efficiency.
        Optimize the code for performance if necessary.

Documentation:

        Write documentation for your code to help future you and others understand how to use and maintain the program.

Deployment:

        Prepare your program for deployment.
        Deploy your program to the production environment.

Maintenance:

        Continuously update the program with improvements or corrections.
        Monitor the program's performance and fix any new bugs that might appear.

----------------------------------------------------------------------

#### Read API Documentation
- takes notes of needs , limits and error codes
- logically think through process
- think of parameters
    - -oT as text
    - -oC as csv

- stage it as a prompt
- paste in ChatGPT
--
I want to write a tool in Python. 
The tool will have the following arguments in argparse, of which at least one will be required: 
-u for username
-e for email
-h for hashed_password
-i for ip_address
-v for vin
-n for name
-a for address
-p for phone number

Optional arguments include:
-OT to output to text file (e.g. -oT output.txt). A file name is required.
-OC to output to CSV file (e.g. -oC output.csv). A file name is required.
-s for size (maximum int of 10000 and minimum of 1 default 1000)
--only-passwords which will only return passwords found in the search for each user found
The script will query an api and require an email address. Here is a sample curl command that should be converted to a
curl 'https://api.dehashed.com/search?query=username:test' \
-u email@email.com: api-key \
-H 'Accept: application/json'
where email@email.com is the user's email variable and api-key is the api variable, which are stored in a separate file
Here is a sample, valid, response:
HTTP Response Code: 200
{"balance":4998, "entries":[



Can you write this code for me?