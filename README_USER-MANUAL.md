Introduction to User manual for the integrated script

Purpose: The purpose of this code is to generate log files that simulate real-time data for analysis and testing. These generated log files serve as a foundation for evaluating system performance, monitoring activities, and assessing the effectiveness of security measures in a controlled environment. The code aims to provide realistic log data that can be used for training, analysis, or validation of security protocols. 
 
Scope: This manual provides detailed guidance on using the log file generation script, covering its features, installation, configuration options, and usage instructions. It is designed to assist users in generating synthetic log files that simulate real-time data for testing and analysis. The manual also includes troubleshooting tips and best practices for using the generated logs in various security scenarios. It is intended for Cyber Threat Intelligence (CTI) analysts, cybersecurity professionals, system administrators, and researchers who require realistic log file data for training, analysis, or validation of security protocols. 

Prerequisites 

System Requirements:  

Python: Requires Python version 3.12.4. Ensure Python is installed and added to your system’s PATH. 

Visual Studio Code: Recommended for reading and editing the code. Download it from https://code.visualstudio.com/. 

Python Extension: Visual Studio Code requires the Python extension to run Python scripts and see the interface. Install the extension from the Extensions Marketplace within VS Code. 

Operating System: Compatible with Windows, macOS, and Linux. 

Disk Space: At least 200 MB of free space to store log files, downloaded code, and temporary files. 

Internet Connection: Required for accessing the code repository on GitHub and downloading necessary libraries. 

Required Libraries:  

Tkinter for building the graphical user interface. 

This version provides clear instructions on how to access, set up, and run the code, ensuring users have everything they need to get started. 

Installation and Setup 

Code Download:  

Download the code from the GitHub repository (LINK FROM THE GITHUB).  
Clone or download the repository to your local machine. Below is the step by step breakdown: 
 
Step 1: Access the GitHub Repository 
Visit the GitHub repository to access the code: GitHub Repository Link (Link). 

Step 2: Clone or Download the Repository 

Option 1: Clone the Repository: If you have Git installed, open your terminal or command prompt and run: 
git clone <repository-link> 

Option 2: Download the ZIP: Click on the "Code" button in the GitHub repository and select "Download ZIP." Extract the ZIP file to your desired location on your local machine. 

Installation Steps:  

Provided below is the step-by-step instructions for downloading the file to your local machine and executing it using appropriate  

Step 1: Open the Project in Visual Studio Code 

Open Visual Studio Code and navigate to the folder where you cloned or extracted the code. 

Use File > Open Folder and select the downloaded folder. 

Step 2: Install Python 

Ensure Python version 3.12.4 is installed on your machine. If not, download it from https://www.python.org/downloads/. 

Step 3: Install Required Libraries 

Open a terminal in Visual Studio Code and run the code as Tkinter comes bundled with installing python. 

Step 4: Install the Python Extension for Visual Studio Code 

Navigate to the Extensions Marketplace in Visual Studio Code and search for the "Python" extension. Click "Install" to enable Python support in VS Code. 

Configuration:  

Configuration files or parameters that need to be adjusted before running the code. 

Step 1: Set File Paths 

Ensure that the paths for saving log files in text and HTML outputs are correctly set in the configuration file or within the code itself. 

Step 2: Verify Environment 

Confirm that all dependencies are installed by running the code in a terminal: 
              python GUI.py 

If everything is set up correctly, the interface should open, or the code should start running. This structured approach ensures users have a clear understanding of how to download, install, and configure your log file code for successful execution. 

4. Overview of the Code 

Structure:  

The code is organised into a single main file that integrates two types of log files - firewall and authentication. Each log file type includes three different attack types, making a total of six attack types. 

Log Files: 

Firewall Log File: Contains records related to firewall activities and incidents. 

Authentication Log File: Records authentication attempts and related security events. 

All logs and their corresponding analysis functions are contained in one file for streamlined access and functionality. The file is named as GUI.py 

Main Components:  

The code has 7 major functions. The first function to execute is where the user is prompted to select the type of log file they want to see, then based on the type of log selected the user is then given the options of attacks under the log file to select for. The next six main functions are the individual attack types which are DDoS attack, Brute Force, Privilege Escalation, Backdoor attack, Malware attack and exfiltration. 
 
The code consists of seven major functions, each playing a specific role in the process of log analysis: 
 

1. User Selection Function: 

Purpose: This function is the entry point of the program. 

Functionality: It prompts the user to select the type of log file they want to analyse (either firewall or authentication). After selecting the log type, it displays a list of possible attack types for the user to choose from. 

 

2. DDoS Attack Analysis: 

Purpose: Analyses firewall logs for signs of Distributed Denial-of-Service (DDoS) attacks. 

Functionality: Detects patterns that indicate a DDoS attempt, such as huge amounts of failed tcp and http connections from a single source within a short time frame. 

3. Brute Force Attack Analysis: 

Purpose: Identifies potential brute force login attempts. 

Functionality: Scans authentication logs for repeated failed login attempts, indicating a possible brute force attack. 

4. Privilege Escalation Detection: 

Purpose: Identifies unauthorised privilege changes. 

Functionality: Analyses logs for events where a user’s permissions are elevated without proper authorization. 

5. Backdoor Attack Analysis: 

Purpose: Detects the presence of backdoor installations. 

Functionality: Looks for unusual or suspicious access points that may have been created by malware or unauthorised users. 

6. Malware Detection: 

Purpose: Scans for malware activity within the logs. 

Functionality: Searches for known malware signatures and suspicious behaviours that could indicate a malware infection. 

7. Exfiltration Detection: 

Purpose: Identifies data exfiltration attempts. 

Functionality: Analyses logs for large data transfers to unauthorised or unknown external locations, which may signal data theft. 

This breakdown provides users with a clear understanding of the code’s organisation and the purpose of each function, making it easier for them to navigate the code. 

Flowchart:  

 

Pseudocode: 

Main Function:  

Display menu:  

Options: Authentication Logs, Firewall Logs, Quit.  

Loop until valid input.  

If Authentication Logs:  

Options: Brute Force, Privilege Escalation, Backdoor Logs.  

Call respective log generation function.  

If Firewall Logs:  

Options: DDOS, Exfiltration, Malware Logs.  

Call respective log generation function.  

Authentication Logs:  

Brute Force Logs:  

Get attack parameters (probabilities, log count, start time).  

Generate logs (successful/failed brute force, disconnections).  

Privilege Escalation Logs:  

Get log count, success rate, privilege, process.  

Generate logs, save to privilege_escalation_logs.txt.  

Backdoor Logs:  

Get log count.  

Generate logs, save to simulated_auth_logs.txt.  

Firewall Logs:  

DDoS Logs: 

Get attack type, connection details.  

Generate logs (normal, attack-specific).  

Save logs in text or HTML format.  

Malware Logs: 

Get  

Generate logs 

Exfiltration Logs: 

Get number of logs, % of normal logs 

Generate logs 

Helper Functions:  

Log Generation: Generate successful, failed, and disconnection logs.  

Time Adjustment: Increment log timestamps.  

File Writing: Save logs to file.  

Main Loop:  

Repeat until quite selected. 

 

5. Usage Instructions 

DDoS Attack: 

To see the DDoS attacks firewall log file, the code needs to be executed as follows: 

The user will be prompted to choose between two types of log files: authentication or firewall. Select Firewall.  

Next, the user will be asked to choose from the three types of attacks under the firewall log file: 1 for DDoS, 2 for Exfiltration, or 3 for Malware. Select 1 to run the DDoS attack log file. 

The user will then be prompted to choose the attack category: syn flood or http flood. Please note that you must type the exact name of the sub-category in full, as shown (either syn flood or http flood). If the full name is not entered correctly, the code will not execute. 

The user will then be asked to choose the desired output file format: either text or html. 

The user will be prompted to specify the number of normal connections they would like to see. Enter any positive number. 

The next step will ask for the number of syn flood / http flood attack entries the user wishes to see. Provide the desired number.  

Then, the user will be asked to specify the packet size for the syn flood / http flood attack. 

After these inputs, the file will be generated and saved to your local machine. Check the Downloads folder for a file named firewall_log. 

Exfiltration attack: 

1: The user will be prompted to choose between two types of log files: authentication or firewall, Select firewall.  

2: Next the user will be asked to chose from three types of attacks: 1 DDoS, 2 Exfiltration, or 3 Malware. Select 2 for exfiltration.  

3: The user will then be prompted to choose how many log entries to be generated. User can enter any number between 1 to 10,000 or even more.  

4: Followed by the user will be asked to enter percentage of normal log entries to be generated: enter the percentage for example 80 meaning 80% percent of the log files that will be generated will be normal log entries for data transfer and the remaining 20% would be malicious log entries which will have exfiltration characteristics.  

Brute Force attack: 

When the program is executed, user faces a command line interface for selectin authentication logs or firewall logs. In firewall log option, user has the option to see log for attacks like exfiltration, DDoS, and Malware. In authentication log option, user has option to see logs for attacks like Brute Force attack, Privilege Escalation, and Backdoor. 

After selecting the Brute Force attack, user will have to input percentage of brute Force attempts. Then user will have to input the percentage of successful brute force attempts. 

After this, user will input the number of logs events he wants to generate. The program also requires use to input starting time to generate log events from that point onward. After these input the desired number of logs will be generated with normal traffic and brute force attack traffic. The logs from the brute force attack will have some entries failed showcasing the brute force attack working in progress and will have some connections successful.  

Backdoor attack: 

In order to access the backdoor attack authentication log file, the following steps are to be followed: 

1. The user must first execute the python code on the terminal using “python Integrated_logs.py” 

2. The user will then be prompted to select two options, 1 for authentication logs and 2 for firewall logs 

3. In this case, the user selects 1 as the input 

4. The user will now be given further options for different authentication log files 

5. The options are 1 for Brute Force Logs, 2 for Privilege Escalation Logs, and 3 for Backdoor Logs. Option 3 is chosen in this case 

6. The user receives a prompt asking them the number of log files they would like to be generated e.g; entering an input of 30 would generate 30 logs 

7. The generated logs get saved to a txt file called “simulated_auth_logs.txt” and gest printed on the terminal  

 

Privilege Escalation Attack: 

To generate Privilege Escalation logs, follow the steps below: 

The user will be prompted to enter the total number of logs they want to generate.  

Input any positive number based on how many log entries you'd like to generate. 

Next, the user will be asked to input the number of successful privilege escalation attempts out of the total logs. 

Specify the number of successful attempts, ensuring it is less than or equal to the total log count. 

The user will then be prompted to enter the type of privilege being escalated. 

Input the name of the privilege you are simulating (e.g., SeDebugPrivilege, SeTakeOwnershipPrivilege). 

Afterward, the user will be asked to specify the process used for the attack. 

Provide the process name that the attacker uses (e.g., cmd.exe, powershell.exe). 

The script will then prompt the user to enter whether administrative access was requested. 

Type Yes or No depending on whether the privilege escalation included an admin access request. 

Once all inputs are entered, the script will generate the specified number of log entries, combining successful and failed privilege escalation attempts based on your input. 

After generating the logs, they will be saved automatically to a file named privilege_escalation_logs.txt in the same directory where the script is located. 

Check the generated log file for the results, including timestamped entries of both successful and failed privilege escalation attempts. 

 

Malicious Software 

The user will be prompted to enter the type of malware attack they want to generate logs for; Data Exfiltration, Key logging, Unauthorized screen capturing, or unwanted monitoring (TCP Connection). 

The user will be prompted to enter the percentage of successful attacks originating from untrusted IPs. 

Once the inputs are provided, the script will generate a series of log entries. These logs will be a combination of successful and unsuccessful attack attempts, based on the success percentage entered by the user.  

The script will create 100 log entries in total, including attacks from both trusted and untrusted IP addresses. 

Trusted IPs will always generate successful attacks. 

Untrusted IPs will have attack outcomes based on the percentage entered by the user in step 2. 

After generating the logs, they will be printed to the terminal for review. Each log entry will be compactly formatted for easy analysis. 

If an invalid attack type is entered, the script will display a list of valid attack types and prompt the user to try again. 

 

 

6. Examples 

Sample Data: 

DDoS Attack: 

The correct process to get the firewall log for syn flood attack and http flood attack under DDoS attack. 

The file gets created in your local machine (computer/laptop). 

 

Exfiltration attack: 

In the image above shows an example how the user input details can be selected from the integrated code to selecting the output of 100 firewall exfiltration logs to be generated with 80% of them being normal log.  

For the user interface design, you can simply select the type of log files and enter input using the graphical user interface 

 

Brute Force Attack 

. 

The image above shows brute force attacks characteristics are shown in log file. In this case program generated 100 log files with 70% of 100 log events being brute force attempts of which only 30% were successful log events. The events capturing time started from 1:00 AM onward with randomise time logging. 

 

Backdoor Attack 

 

The image above provides an example of how the authentication logs of different kinds can be selected as user input from the integrated code. In this case, backdoor logs are selected. The code allows the user to input the number of backdoor logs they would like to be generated. In the above case, 20 log files are generated on the terminal. These are also saved to the computer in a text file. As can be seen multiple sessions for the same user root have been opened with different IP Addresses and in a short interval of time. 

A screenshot of a computer

Description automatically generated 

Privilege Escalation Attack: 

 

 

In this example, the user selected to generate a total of 10 logs, with 4 successful privilege escalation attempts using the SeDebugPrivilege privilege and the process cmd.exe. The user also indicated that administrative access was requested. 

After inputting these details, the script will generate and save the log entries in a file named privilege_escalation_logs.txt, which will contain both successful and failed attempts. 

  

For the user interface, you can simply enter the required information step-by-step and the logs will be generated automatically based on the inputs provided. 

 

Malicious Software 

A black screen with many small colored text

Description automatically generated with medium confidence 

 

Each log entry is timestamped and includes essential details such as the source and destination IP addresses, the port, protocol, event type, and whether the attack was successful or not. Successful attacks are marked with "ALERT" and show "ACCESS GRANTED," while unsuccessful attempts are labelled "INFO" with "ACCESS DENIED." The event type is either "EVENT" for successful attacks or "ATTEMPT" for failed ones. In this specific example, the user set the success rate for untrusted IP addresses at 30%, so 30% of the logs show successful keylogging attempts, and the remaining logs reflect failed attempts. The generated logs also vary in terms of source and destination IPs, ports, and protocols (TCP, UDP, ICMP), providing a diverse set of entries that reflect real-world firewall monitoring of malware activities like Keylogging. # 

 

Use Cases: 

Cybersecurity Training and Awareness 

Scenario: Security professionals or students can utilize the code to simulate various cyber attacks within a controlled environment. This approach enhances their understanding of attack patterns and equips them with the skills to develop effective defensive strategies. 

Application: Conduct training sessions or workshops focused on incident response and threat detection techniques. 

Penetration Testing 

Scenario: Ethical hackers can employ the code during penetration testing engagements to replicate diverse attack vectors. This simulation allows for the identification of vulnerabilities within systems and applications. 

Application: Perform security assessments that enhance organizational security by pinpointing weaknesses before they can be exploited. 

Threat Detection Systems 

Scenario: Incident response teams can utilize the code to rehearse their response to various attack scenarios, refining their incident response plans and ensuring team readiness. 

Application: Conduct tabletop exercises or live simulations to prepare for potential real-world cyber incidents. 

Research and Development 

Scenario: Researchers can apply the code to analyze the behaviors of different attacks and their implications on systems, facilitating the development of new detection methods and defensive technologies. 

Application: Conduct academic studies or write research papers aimed at understanding attack methodologies to improve cybersecurity measures. 

Tool Development 

Scenario: Developers can leverage the code to create tools or platforms that incorporate simulated attack characteristics, enabling automated testing and analysis of security measures. 

Application: Develop custom security testing tools or frameworks that enhance existing security products. 

Policy and Compliance Testing 

Scenario: Organizations can apply the code to evaluate the effectiveness of their security policies against specific attack types, ensuring compliance with industry regulations. 

Application: Conduct regular audits and compliance checks to validate that security measures align with best practices and regulatory requirements. 

 

7. Troubleshooting 

Common Errors:  

List common errors or issues that users may encounter and how to resolve them. 

Input Syntax Error – One of the most common issues is entering the wrong syntax when prompted for input. Ensure that you follow the provided instructions carefully, particularly when selecting log file types or attack categories. For example, when choosing a log type, the required syntax is clearly indicated in brackets. Inputting anything other than the exact text will prevent the code from executing correctly. 
 

Using Negative Numbers: When entering the number of normal connections or attack entries, make sure to input a positive integer. Negative numbers or non-numeric inputs will result in an error.  
 

File Not Generated: If the log file is not generated after running the code, check your system's download folder. Ensure that you have the necessary permissions to save files on your local machine and that no file-naming conflicts are present. 

Debugging Tips:  

Provide tips for debugging the code or identifying issues. 

Check Code for Comments: The code includes detailed comments to help you understand where an error might have occurred. When the code fails, review the console or terminal output for these comments on the Visual Studio code, which will indicate the specific part of the code causing the issue. 
 

Review Input Prompts: If the program doesn't proceed to the next step, revisit the input prompts to ensure that all required fields were entered correctly, such as the log file or attack type. 
 

Check Python: Check whether you have python downloaded in your computer. Ensure you're using the correct version of Python (3.12.4) to avoid compatibility issues. Running the code on an outdated version may lead to unexpected failures. 

9. Frequently Asked Questions (FAQs) 

List questions that might arise from users and provide concise answers. 

10. Version History 

Graphical User Interface (GUI): 

Description: This version runs locally on your machine and uses a graphical interface (such as PyQt or Tkinter) to provide a more traditional desktop experience. 

Output: The output in the GUI version is generally produced as text files or other locally accessible formats. It is designed to integrate seamlessly with your desktop environment, allowing you to access and manipulate the files directly on your system. 
 

12. Appendices 

Glossary: 

The following are some of the technical terms used in the manual. 

 

Cyber Threat Intelligence - the process of gathering and analyzing information about potential or existing threats to protect systems and data from cyberattacks. 

Configuration – the setup and arrangement of system settings, components, or software to ensure proper functionality and security. 

Cybersecurity – the practice of protecting systems, networks, and data from digital attacks, unauthorized access, and damage. 

Protocols – are standardized rules or procedures that govern data transmission and communication between devices in a network. 

Python - a high-level, versatile programming language commonly used for scripting, automation, and data analysis. 

Log Files – are records generated by a system or application that capture activities, events, and errors for analysis and troubleshooting. 

DDoS attack - a Distributed Denial-of-Service (DDoS) attack involves overwhelming a server or network with excessive traffic, causing it to slow down or crash. 

Brute force attack – is a hacking technique where multiple password attempts are made rapidly to guess the correct credentials and gain unauthorized access. 

Privilege Escalation – is the act of gaining higher access permissions or control in a system than is normally allowed, often by exploiting vulnerabilities. 

Backdoor attack – is an attack where an unauthorized entry point is secretly installed in a system, allowing future access without detection. 

Malware attack – is an attack where malicious software is introduced into a system to cause harm, steal data, or disrupt operations. 

Exfiltration attack – is the unauthorized transfer of data from a computer system, usually by a malicious actor. 

Penetration – is the act of successfully bypassing security measures and gaining unauthorized access to a system. 

Troubleshooting - the process of identifying and resolving problems or issues within a system, software, or hardware. 

Debugging - the process of identifying, analysing, and fixing bugs or errors in a code or program. 
 

References:  

What is PseudoCode: A Complete Tutorial - GeeksforGeeks 

 
