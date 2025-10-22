# Monitoring
This application provides your a simple monitoring tool to see if your serivces are up or not.
The system can do HTTP and PING checks on a interval or you can leave it of when your IT department have akknoled a problem you can change the status.

## Installation
For this project you can use docker to deploy this application or use it in a virtual enviroment (you might have issues with the packages with this).

### Docker Installation
- Clone the repository to a server with docker installed
- run ```docker compose up --build ```
- run ```docker compose up -d ```to run it in daemon mode.

Docker will install the python application an the dependencies using the Dockerfile defined in this project using the requiremetns file.
The database is kept on sqllite because this application wil not use a lot of resoureces , if you are using many resources for this you might have to add a database to the docker-compose file to extend the service.
And some code changes will be also required.


## Features
- List Servers
- See history of a server
- Add servers (admin function)
- Timeline with issues
- Schedule a maintaince period (will only show on the day of the maintance)
- Add HTTP check to a server
- Enable or disbale a HTTP check of a server
- Manual check a HTTP check of a server.
- Add PING check to a server
- Enable of disable a PING check of a server.
- Edit the name of the server.
- Update the status of the server manualy.
- When a service goes down and you use the HTTP check , when this service recovers the status wil automaticly update after the interval.
- Manage statues (Add Name, Choose color and basic icons and delete statuses)
- Active Directory is backend for the login