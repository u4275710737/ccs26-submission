# Artifact Submission | ACM CCS 2026 - Cycle A | Is Echo Scanning Worth it? Exploring the Global Landscape of Echo Servers for Censorship Analyses

In the following, we briefly describe the structure of this artifact, containing our scanning tools, data, and analysis scripts. Afterwards, we present the setup, how to use our artifact, and further notes on the used IP2Location database.

## Disclaimer

When reading the paper, the contained data and analysis scripts to reproduce the figures from the paper are the most important parts. They can be easily set up and executed with Python (see below). The scanning tools need more extensive preparation with Kotlin, Java, maven, ZMap, and Nmap and one should take caution when using these tools as you should not scan networks you do not own without permission or extensive preparation beforehand.
In a potential later artifact evaluation, we will provide an appropriate testing environment for our scanning tools.

## Important Files and Folder Structure

```text
Artifact/
├── Censor-Core (Core system of Censor-Scanner, the underlying tool we used)
├── Censor-EchoServerEvaluator (Submodule for our daily scans, including execution of zmap and nmap)
├── Censor-ProbeScanner (Submodule for executing censorship probes for discovery and reproducibility)
├── data (Folder containing data of our scans and analysis scripts)
    ├── daily scans (Folder containing our daily scan data, split for TCP and UDP)
    ├── pcaps (Pcaps from our censorship discovery and Echo reproduction probes, anonymized)
    ├── IP2LOCATION-LITE-DB5.BIN (IP2Location database file, see below for further information)
    ├── as_extractor.py (Analyzes AS information for a specific scan day, optionally restricted by country)
    ├── map_creator.py (Main analysis script for all numbers and visualizations of our daily scan in the paper)
    ├── ...[Automatically generated files as gif, json, jpeg, png, or html]
    ├── nmap_extractor.py (Analyzes the nmap scan output from our daily can and outputs numbers from paper)
    └── requirements.txt (Contains all Python requirements)
├── python_util (Contains useful scripts to start Echo and simple TCP/UDP servers)
└── README.md
```

Notably, all .pcapng, .json, and .BIN files are stored in git lfs.

## PCAP Anonymization

In order to keep the specific IP adresses of our used vantage points anonymous, we exchanged the IP adresses in our PCAPs. We use the following mapping:

```
Outside Analyzed Countries Vantage Point    = 10.10.10.1
Chinese Vantage Point                       = 10.10.10.2
Indian Vantage Point                        = 10.10.10.3
Iranian Vantage Point                       = 10.10.10.4
Kazakh Vantage Point                        = 10.10.10.5
Russian Vantage Point                       = 10.10.10.6
```

After review, the "Outside Analyzed Countries" vantage point will be replaced with the proper country name.

## Setup

In a future artifact evaluation, we will provide Docker containers and Docker Compose scripts to ease the setup process. We could not do this for the initial submission due to time constraints.

### Scanning Tools

Our main tools, contained in the `EchoServerEvaluator` and `ProbeScanner` submodules, are built with Java 21, Kotlin 2.1.10, and use Maven for dependency management. After installing Java 21, and Maven, the tools can be built by executing `mvn clean install`, which creates an `apps` folder containing the built jars and used libraries. For more notes on how to use these tools, see our Usage section below.

#### Installing and Preparing ZMap and Nmap

For the daily scan, contained in `EchoServerEvaluator`, you need to install ZMap and Nmap first. Depending on your OS, this can be done with `sudo apt install zmap` and `sudo apt install nmap`. More specifically, we used ZMap version `2.1.1` and Nmap version `7.94SVN`.

Notably, ZMap needs specific capabilities to conduct the scan successfully. A helper script to set them is contained in `Censor-EchoServerEvaluator/scripts/prepare_zmap.sh`.

### Analysis Scripts

Our surrounding analyses scripts, contained in `data`, use Python. We used Python version `3.10.14`. All requirements to run the analyses scripts are contained in `data/requirements.txt` and can be install with `pip install -r requirements.txt` in the `data` folder. We recommend creating a virtual environment with venv / pyenv or similar.

## Usage

### Scanning Tools

In the following, we describe how to use our scanning tools, consisting of our Echo server evaluator and our probe scanner.

#### Echo Server Evaluator

Here is an example command to execute the daily scan for TCP:

`sudo java -jar censor-echoserverevaluator-1.1.0-SNAPSHOT.jar`

Notably, there are many parameters that can be used to influence the scanning behavior. One of the most important ones is `-zmapDenylist`, which specifies a denylist file for the ZMap scan. This file needs to be created before starting to scan; otherwise, an exception is intentionally thrown. There are other additional parameter that can be used to configure the ZMap scan, such as `-zmapThreads`, `-zmapBandwith`, and `-zmapPPS`. These specify the number of used threads, the maximum used bandwidth, and the maximum packets per second, respectively. Another important parameter is `-scanUdp`, which, if present, conducts an UDP ZMap scan instead of TCP. `-skipZmap` and `-skipNmap` can be used to skip the corresponding step in the daily scan. Finally, `-nmapSampleSize` specifies the sample size taken for the Nmap scan, defaulting to 1%.

There are some more not so important parameters, which are documented in code in the corresponding config in: `/Censor-EchoServerEvaluator/src/main/kotlin/de/rub/nds/censor/echo/config/EchoEvalConfig.kt`.

#### Probe Scanner

Here is an example command to execute the ProbeScanner:

`sudo java -jar censor-probescanner-1.1.0-SNAPSHOT.jar -ip X.X.X.X -hostname gaytoday.com -path /gay -dnsHostname gaytoday.com -echo`

This executes a probe scan against the specified IP (redacted here), and uses the specified hostname, path value, and DNS hostname for the corresponding probes that check for HTTP Host header-based, TLS SNI-based, HTTP path-based, and DNS censorship. If these parameters are not present, the tool uses the default values contained in the code. Notably, the `-echo` parameter is given to perform this probe scan against an Echo server, running on port 7 on the specified IP. Omitting this parameter, executes the probes against our simple server running at the specific IP, with the corresponding protocol's port such as 443 for TLS. Another important parameter is `-mimicClientPort`, which uses the correct client port (e.g., 53 for DNS) instead of a random one. This was important to trigger some censorship via Echo scanning, such as the DNS censorship observed in China.

More information about all parameters and their meaning can be found in the code that specifies the config in: `/Censor-ProbeScanner/src/main/kotlin/de/rub/nds/censor/probescanner/main/config/CensorScannerConfig.kt`.

### Analyses Scripts

In the following, we describe how to use our three analysis scripts.

#### Main Analysis

The main analysis, which analyzes the daily scan data and outputs all statistics and visualizations from the paper, is contained in the file `map_creator.py`. It can be executed with: `python map_creator.py`.

It has four main constants on top of the file, which can be adjusted:
- `DIR_WITH_DATA` should remain unchanged as this is a constant to the directory with the data.
- `LIMIT_SINGLE_OUTPUT` is a list of days to limit the output of a scatter plot for, currently not used in the paper.
- `WORKING_FILTER` is used to filter the working Echo servers for which are reachable for all `WORKING_FILTER` last days of the scan. These are then used at the end to create a scatter plot and choropleth. Notably, these are not used in the paper directly, as we present the choropleth for the first scan day of all servers. The default is 14, filtering to the Echo servers that are reachable for the whole scan duration.
- `DAY_ANALYSIS` specifies a specific day that is used for the hourly analysis of reachable Echo servers on one day. This defaults to the last scanning day, which is consistent with our paper.

#### AS Extraction

The AS extraction is contained in the file `as_extractor.py`, which can be executed with: `python as_extractor.py`.

It has three main constants on top of the file, which can be adjusted:
- `DIR_WITH_DATA` should remain unchanged as this is a constant to the directory with the data.
- `DAY_ANALYSIS` is the day used for the AS analysis, defaulting to the 14th of June 2025, which is consistent with the data in the paper.
- `COUNTRY_RESTRICTION` can be used to restrict the AS analysis to a specific country by its 2-digit country code (e.g., KR for South Korea). By default, it is done for all countries.

#### Nmap Analysis

The Nmap analysis is contained in the file `nmap_extractor.py`, which can be executed with: `python nmap_extractor.py`.

It has no further constants that can be adjusted, as it simply analyzes all nmap outputs contained in the `daily_scans` folder.

### Echo Server for Testing

You can launch a local TCP Echo server for testing purposes in `python_util` with `python3 echo_tcp.py`. Similarly, also for UDP. By default, it starts a sever on port 7, as defined for the Echo protocol; however, this can be adjusted via a constant at the top of the file.

## IPLocation Database

The [IP2Location FAQ](https://lite.ip2location.com/faqs) states:

```
You can redistribute one copy of the LITE database with your application with attribution. However, you need to inform all users to register for an individual license in https://lite.ip2location.com to download updates. Third party database repository is not allowed.
```

This is why we redistribute the one database file that we obtained when we executed our scan`IP2LOCATION-LITE-DB5.BIN`. Note that while it is possible to download an up-to-date version of the database from their website, the database obtained at the time of the scan more accurately reflects the appropriate IP geolocations at the time of the scan.

### Acknowledgement

Our artifact uses the IP2Location LITE database for <a href="https://lite.ip2location.com">IP geolocation</a>.
