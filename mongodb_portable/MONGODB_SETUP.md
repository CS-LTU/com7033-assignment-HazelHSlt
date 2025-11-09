AI declaration:
Github copilot was used for portions of the planning, research, feedback and editing of the software artefact. Mostly utilised for syntax, logic and error checking with ChatGPT and Claude Sonnet 4.5 used as the models.


MongoDB Portable Setup Guide:
If unable to install a MongoDB service due to lacking administrator privilages on the current system, then this portable MongoDB instance should be run first and left running everytime the rest of the project is run locally.

To use, first go to, download and extract the contents of this folder "mongodb-win32-x86_64-windows-8.2.1" to the root of this folder "mongodb_portable" (so the "start_mongodb.ps1" file is in the same folder as "bin") from "https://fastdl.mongodb.org/windows/mongodb-windows-x86_64-8.2.1.zip"

The project should be setup to run with MongoDB on the default port of `27017`, to run it portably open powershell from the windows start menu and use the command "cd" to navigate to the root of this folder "mongodb_portable". 

Then run the .ps1 file with ".\start_mongodb.ps1". It will automatically run all the remaining commands to initiate a local mongodb connection, it is recommended to use a program such as "mongodb compass" to view and connect to the contents of its database to manage and verify its function.



