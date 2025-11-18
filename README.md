# Booby Pot
#### Description:
> A simple production ftp/http honeypot, with SIEM-like dashboard web UI.
## Table of Contents
- [Installation](#installation)
- [Project Tree](#project-tree)
- [Usage](#usage)
- [Dashboard](#dashboard)
***
### Installation

#### Prerequisites:
- `Docker` 
- `Docker-compose`

#### To install:
1. Clone the repo: `$ git clone https://github.com/WithoutName12/BoobyPot.git`
2. Navigate into the folder: `$ cd BoobyPot`
3. Start docker daemon (`systemd`): `$ sudo systemctl start docker` 
4. Start the app: `$ docker-compose up -d`


### Project Tree:
```
    ├── dashboard
    │   ├── app.py
    │   ├── Dockerfile
    │   ├── requirements.txt
    │   └── templates
    │       ├── files_ftp.html
    │       └── logs.html
    ├── honeypot
    │   ├── config.ini
    │   ├── Dockerfile
    │   ├── main.py
    │   ├── requirements.txt
    │   └── templates
    │       └── 80
    │           ├── 400
    │           ├── 404
    │           ├── default_headers
    │           ├── default_page
    │           └── incorrect_password
    ├── docker-compose.yaml
    └── README.md
```

> #### `honeypot/`
- `main.py` - Actual honeypot program, written in python. Listens to sockets, handles connections and writes logs
- `requirements.txt` - List of libraries required by honeypot program
- `config.ini` - Configuration file for ftp user and password and a banner, which honeypot will use
- `Dockerfile` - Docker Build instructions
- `templates/` - Templates for responses 
    - `80/` - Templates for http responses
        - `400` - Response for a **Bad Request**
        - `404` - Response for **Not Found**
        - `default_headers` - Default response headers
        - `default_page` - Default response body
        - `incorrect_password` - Response body when password is incorrect
> #### `dashboard/`
- `app.py` - Flask application as a back end of web UI
- `requirements.txt` - List of libraries required by dashboard program
- `Dockerfile` - Docker build instructions
- `templates/` - Jinja templates
    - `logs.html`
    - `files_ftp.html`

***

### Usage:
```
usage: main.py [-h] [-p [{21,80} ...]] [-H [HOST ...]]

Simple honeypot for production

options:
  -h, --help            Show the help menu and exit
  -p, --port [{21,80} ...]
                        Ports that honeypot will listen to (Default: [21, 80])
  -H, --host [HOST ...]
                        Interfaces honeypot will listen to (Default: 0.0.0.0 = All Interfaces)
```

To change options of honeypot, change `docker-compose`:

`CMD ["python", "main.py]"`

Default runs on all interfaces (`0.0.0.0`) on `21` and `80`. Add options at it follows:

`CMD ["python", "main.py, "-p21"]`, Will run it on all interfaces port `21`

To run honeypot and dashboard in docker, go into project directory and run:

`$ docker-compose up -d`

Make sure *docker*, *docker-compose* is installed and docker daemon is running.
Booby Pot supports both active and passive ftp connections.

#### `honeypot/config.ini`:
Under `[ftp]` change example user, password, banner for ftp *(Do not add quotes)*.

**Example:**
```
user = system (default - "admin", if not provided) 
password = password (default - "admin", if not provided)
banner = 220 Welcome to Pure-FTPd [privsep] (TLS)
(default - "220 (vsFTPd 3.0.3) Ubuntu Linux ready.", if not provided)
```
***
#### Dashboard
```
Filters honeypot logs and serves ftp files.
```
To access dashboard navigate to `http://172.20.0.10:8000/`
##### Syntax: 
**Search Attributes:**
- `time` - Time in ISO format
- `remote_ip` - Client IP address
- `remote_port` - Client port number
- `local_port` - Server's port number
- `data` - Actual data sent by client

***NOTE:*** Values without attribute will search inside data field 


**Operators**:
- `&&` - And Operator
- `||` - Or operator 

To make strict search queries use `""` around attribute value: `remote_ip:"21"` 

**Examples:**

`local_port: 21 && time: 2025` - Will search logs where `local_port` field has '21' in it and `time` field has *'2025'* in it.

`local_port: "80" || remote_ip: "127.0.0.1"` - Will search logs where `local_port` field **strictly** equals to *'80'* or `remote_ip` field **strictly** equals to *'127.0.0.1'*.

*** 

To add maximum log limit change input field *(Default Limit: 50)*.

To access FTP files click on Files hyperlink in the upper right corner.

To reset all filters and get newer logs use `Reset` button.

*** 

### Troubleshooting
- If `docker-compose up -d` shows `failed to create network boobypot_dashnet: Error response from daemon: invalid pool request: Pool overlaps with other one on this address space`
1. Run `docker network ls`, which will shows all docker networks.
2. Inspect networks one by one `docker network inspect <network-name>` to see their subnets.
3. Note all the subnets and change docker-compose network subnet and static ip of dashboard container to free ones.

***

## Reporting Issues

If you encounter any other errors or problems that are not listed here, feel free to create a new issue in the [GitHub Issues tab](https://github.com/WithoutName12/BoobyPot/issues).  

I appreciate your feedback and contributions!
